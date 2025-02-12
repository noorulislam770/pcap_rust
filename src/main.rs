use mysql::prelude::*;
use mysql::*;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
struct CdrRecord {
    cdr_id: Vec<u8>,
    filename: Vec<u8>,
    tar_positions: Vec<u8>,
}

fn log_message(message: &str, is_error: bool) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if is_error {
        eprintln!("[{}] ERROR: {}", timestamp, message);
    } else {
        println!("[{}] INFO: {}", timestamp, message);
    }
}

fn check_directory(path: &str) -> std::io::Result<()> {
    if !Path::new(path).exists() {
        log_message(&format!("Creating directory: {}", path), false);
        fs::create_dir_all(path)?;
    } else {
        log_message(&format!("Directory exists: {}", path), false);
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Database credentials
    let db_user = "monitor";
    let db_pass = "xflow";
    let db_name = "voipmonitor_temp";
    let db_host = "172.16.11.36";
    let db_port = 3306;

    // Paths
    let rtp_tar_path = "/isilon/media-s2/media-s2-2/2025-02-11/09/02/RTP/rtp_2025-02-11-09-02.tar";
    let sip_pcap_dir = "/root/manual_SIP_RUST/pcaps";
    let rtp_pcap_dir = "/tmp/RTP_pcaps_RUST/";
    let merged_pcap_dir = "/root/manual_SIP_RUST/merged_pcaps";
    let output_csv = "/root/manual_SIP_RUST/pcap_processing_times_RUST.csv";

    // Verify tar file exists
    if !Path::new(rtp_tar_path).exists() {
        log_message(&format!("RTP TAR file not found: {}", rtp_tar_path), true);
        return Ok(());
    }

    // Create and verify directories
    for dir in [sip_pcap_dir, rtp_pcap_dir, merged_pcap_dir] {
        if let Err(e) = check_directory(dir) {
            log_message(
                &format!("Failed to create/verify directory {}: {}", dir, e),
                true,
            );
            return Ok(());
        }
    }

    // Create CSV file
    let mut csv_file = match File::create(&output_csv) {
        Ok(file) => file,
        Err(e) => {
            log_message(&format!("Failed to create CSV file: {}", e), true);
            return Ok(());
        }
    };

    // Write CSV header
    writeln!(
        csv_file,
        "start_time,rtp_end_time,rtp_execution_time,merge_end_time,merge_execution_time,cdr_id,filename,tar_positions"
    )?;

    let start_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    log_message("Script started", false);

    // Connect to database
    log_message("Connecting to database...", false);
    let opts = Opts::from_url(&format!(
        "mysql://{}:{}@{}:{}/{}",
        db_user, db_pass, db_host, db_port, db_name
    ))?;
    let pool = Pool::new(opts)?;
    let mut conn = pool.get_conn()?;
    log_message("Database connection established", false);

    // Your existing query
    let query = r#"
        SELECT
            cdr.id AS CDR_ID,
            cdr_next.fbasename AS FILENAME,
            GROUP_CONCAT(cdr_tar_part.pos ORDER BY cdr_tar_part.pos ASC SEPARATOR ',') AS TAR_POSITIONS
        FROM cdr
        INNER JOIN cdr_next ON cdr.id = cdr_next.cdr_ID
        INNER JOIN cdr_tar_part ON cdr.id = cdr_tar_part.cdr_id
        WHERE cdr.calldate >= '2025-02-11 09:02:00'
          AND cdr.calldate < '2025-02-11 09:03:00'
          AND cdr.id_sensor = 15
        GROUP BY cdr.id, cdr_next.fbasename
        ORDER BY cdr.id ASC;
    "#;

    log_message("Executing database query...", false);
    let results: Vec<CdrRecord> =
        conn.query_map(query, |(cdr_id, filename, tar_positions)| CdrRecord {
            cdr_id,
            filename,
            tar_positions,
        })?;
    log_message(
        &format!("Found {} records to process", results.len()),
        false,
    );

    // Convert binary data to appropriate types
    for record in results {
        let cdr_id_str = String::from_utf8(record.cdr_id.clone())?;
        let cdr_id = cdr_id_str.parse::<u64>()?; // Use u64 instead of u32
        let filename = String::from_utf8(record.filename.clone())?;
        let tar_positions = String::from_utf8(record.tar_positions.clone())?;

        log_message(&format!("Processing CDR ID: {}", cdr_id), false);

        let rtp_pcap_file = format!("{}/{}.pcap", rtp_pcap_dir, filename);
        let sip_pcap_file = format!("{}/{}.pcap", sip_pcap_dir, filename);
        let merged_pcap_file = format!("{}/{}.pcap", merged_pcap_dir, cdr_id);

        // Log file paths for debugging
        log_message(&format!("RTP PCAP path: {}", rtp_pcap_file), false);
        log_message(&format!("SIP PCAP path: {}", sip_pcap_file), false);
        log_message(&format!("Merged PCAP path: {}", merged_pcap_file), false);

        if !tar_positions.is_empty() {
            let rtp_start_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            // Extract RTP PCAP
            log_message(
                &format!("Extracting RTP PCAP for CDR ID: {}", cdr_id),
                false,
            );
            let xfvm_command = format!(
                "--untar-gui={} {}.pcap {} {}",
                rtp_tar_path, filename, tar_positions, rtp_pcap_file
            );
            log_message(
                &format!("Running xfvm command: xfvm -kc {} \n\n\n", xfvm_command),
                false,
            );

            let status = Command::new("xfvm")
                .arg("-kc")
                .arg(&xfvm_command)
                .status()?;

            if status.success() {
                let rtp_end_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let rtp_execution_time = rtp_end_time - rtp_start_time;
                log_message(
                    &format!("RTP extraction successful for CDR ID: {}", cdr_id),
                    false,
                );

                // Check SIP PCAP
                if Path::new(&sip_pcap_file).exists() {
                    log_message(&format!("Found SIP PCAP for CDR ID: {}", cdr_id), false);

                    log_message("before merge\n\n", false);

                    let merge_start_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

                    // Merge PCAPs
                    log_message(&format!("Merging PCAPs for CDR ID: {}", cdr_id), false);
                    log_message("before tcpslice", false);
                    let status = Command::new("tcpslice")
                        .arg("-w")
                        .arg(&merged_pcap_file)
                        .arg(&sip_pcap_file)
                        .arg(&rtp_pcap_file)
                        .status()?;

                    if status.success() {
                        log_message("after tcpslice", false);
                        log_message("after merge successfull \n\n", false);
                        let merge_end_time =
                            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                        let merge_execution_time = merge_end_time - merge_start_time;
                        log_message(
                            &format!("Successfully merged PCAPs for CDR ID: {}", cdr_id),
                            false,
                        );

                        writeln!(
                            csv_file,
                            "{},{},{},{},{},{},{},{}",
                            start_time,
                            rtp_end_time,
                            rtp_execution_time,
                            merge_end_time,
                            merge_execution_time,
                            cdr_id,
                            filename,
                            tar_positions
                        )?;
                    } else {
                        log_message(
                            &format!("Failed to merge PCAPs for CDR ID: {}", cdr_id),
                            true,
                        );
                    }
                } else {
                    log_message(
                        &format!(
                            "SIP PCAP not found: {} for CDR ID: {}",
                            sip_pcap_file, cdr_id
                        ),
                        true,
                    );
                }
            } else {
                log_message(
                    &format!("Failed to extract RTP PCAP for CDR ID: {}", cdr_id),
                    true,
                );

                // Attempt to move SIP PCAP
                if Path::new(&sip_pcap_file).exists() {
                    match fs::rename(&sip_pcap_file, &merged_pcap_file) {
                        Ok(_) => log_message(
                            &format!("Moved SIP PCAP to merged directory for CDR ID: {}", cdr_id),
                            false,
                        ),
                        Err(e) => log_message(
                            &format!("Failed to move SIP PCAP for CDR ID {}: {}", cdr_id, e),
                            true,
                        ),
                    }
                }
            }
        } else {
            log_message(
                &format!("No TAR positions found for CDR ID: {}", cdr_id),
                true,
            );

            // Attempt to move SIP PCAP
            if Path::new(&sip_pcap_file).exists() {
                match fs::rename(&sip_pcap_file, &merged_pcap_file) {
                    Ok(_) => log_message(
                        &format!("Moved SIP PCAP to merged directory for CDR ID: {}", cdr_id),
                        false,
                    ),
                    Err(e) => log_message(
                        &format!("Failed to move SIP PCAP for CDR ID {}: {}", cdr_id, e),
                        true,
                    ),
                }
            }
        }
    }

    let end_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let execution_time = end_time - start_time;
    let hours = execution_time / 3600;
    let minutes = (execution_time % 3600) / 60;
    let seconds = execution_time % 60;

    log_message(
        &format!(
            "Script completed. Total execution time: {}h {}m {}s",
            hours, minutes, seconds
        ),
        false,
    );

    Ok(())
}
