use mysql::prelude::*;
use mysql::*;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
struct CdrRecord {
    cdr_id: Vec<u8>,
    connect_duration: Option<Vec<u8>>,
    filename: Vec<u8>,
    tar_positions: Option<Vec<u8>>,
}

fn log_perf(operation: &str, duration: f64) {
    println!("[PERF] {}: {:.2}s", operation, duration);
}

fn log_error(message: &str) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    eprintln!("[{}] ERROR: {}", timestamp, message);
}

fn check_directory(path: &str) -> std::io::Result<()> {
    if !Path::new(path).exists() {
        fs::create_dir_all(path)?;
        println!("Created directory: {}", path);
        let metadata = fs::metadata(path)?;
        println!("Directory permissions: {:o}", metadata.permissions().mode());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let script_start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();

    // Database configuration
    let db_user = "monitor";
    let db_pass = "xflow";
    let db_name = "voipmonitor_temp";
    let db_host = "172.16.11.36";
    let db_port = 3306;

    // File paths
    let rtp_tar_path = "/isilon/media-s2/media-s2-2/2025-02-11/09/02/RTP/rtp_2025-02-11-09-02.tar";
    let sip_tar_path =
        "/isilon/media-s2/media-s2-2/2025-02-11/09/02/SIP/sip_2025-02-11-09-02.tar.gz";
    let sip_pcap_dir = "/tmp/SIP_pcaps_RUST/";
    let rtp_pcap_dir = "/tmp/RTP_pcaps_RUST/";
    let merged_pcap_dir = "/root/MP_NOOR_RUST/merged_pcaps";
    let output_csv = "/root/MP_NOOR_RUST/pcap_processing_times_RUST.csv";

    // Verify tar files exist
    for path in &[rtp_tar_path, sip_tar_path] {
        if !Path::new(path).exists() {
            log_error(&format!("TAR file not found: {}", path));
            return Ok(());
        }
    }

    // Create required directories
    for dir in &[sip_pcap_dir, rtp_pcap_dir, merged_pcap_dir] {
        if let Err(e) = check_directory(dir) {
            log_error(&format!("Failed to create directory {}: {}", dir, e));
            return Ok(());
        }
    }

    // Create and initialize CSV file
    let mut csv_file = File::create(&output_csv)?;
    writeln!(
        csv_file,
        "cdr_id,query_time,rtp_time,sip_time,merge_time,total_time"
    )?;

    // Database connection
    println!("Connecting to database...");
    let db_start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
    let opts = Opts::from_url(&format!(
        "mysql://{}:{}@{}:{}/{}",
        db_user, db_pass, db_host, db_port, db_name
    ))?;
    let pool = Pool::new(opts)?;
    let mut conn = pool.get_conn()?;

    // Execute database query
    let query = r#"
        SELECT cdr.id ,MAX(cdr.connect_duration) , cdr_next.fbasename, GROUP_CONCAT(cdr_tar_part.pos ORDER BY cdr_tar_part.pos ASC SEPARATOR ',') AS tar_positions
    FROM cdr
    INNER JOIN cdr_next ON cdr.id = cdr_next.cdr_ID
    LEFT JOIN cdr_tar_part ON cdr.id = cdr_tar_part.cdr_id
    WHERE cdr.calldate >= '2025-02-11 09:02:00' AND cdr.calldate < '2025-02-11 09:03:00' AND cdr.id_sensor = 15
    GROUP BY cdr.id, cdr_next.fbasename, cdr.connect_duration
    ORDER BY cdr.id ASC;
    "#;

    let results: Vec<CdrRecord> = conn.query_map(
        query,
        |(cdr_id, connect_duration, filename, tar_positions)| CdrRecord {
            cdr_id,
            connect_duration,
            filename,
            tar_positions,
        },
    )?;

    let db_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64() - db_start;
    log_perf("Database query completed", db_time);

    let num_records = results.len();
    println!("Processing {} records...", num_records);

    for record in &results {
        let record_start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();

        // Process filenames
        let filename = String::from_utf8(record.filename.clone())?;
        let updated_filename = {
            let tmp = filename.replace(['[', ']'], "_");
            if tmp.starts_with('-') {
                tmp.chars()
                    .enumerate()
                    .map(|(i, c)| if i == 0 && c == '-' { '*' } else { c })
                    .collect::<String>()
            } else {
                tmp
            }
        };

        let cdr_id = String::from_utf8(record.cdr_id.clone())?.parse::<u64>()?;

        let connect_duration = record
            .connect_duration
            .as_ref()
            .and_then(|v| String::from_utf8_lossy(v).parse::<u32>().ok())
            .unwrap_or(0);

        println!("Processing CDR ID: {}", cdr_id);

        // Define file paths
        let rtp_pcap_file = format!("{}/{}.pcap", rtp_pcap_dir, filename);
        let sip_pcap_file = format!("{}/{}.pcap", sip_pcap_dir, filename);
        let merged_pcap_file = format!("{}/{}.pcap", merged_pcap_dir, cdr_id);

        let mut rtp_time = 0.0;
        let mut sip_time = 0.0;
        let mut merge_time = 0.0;

        let has_rtp = connect_duration > 0 && record.tar_positions.is_some();

        if !has_rtp {
            println!("Processing SIP PCAP only (no RTP data)...");
            let sip_start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();

            let sip_extract_command = format!(
                "tar --use-compress-program='pigz -p 4' --wildcards -xOf '{}' '{}.pcap*' > {}",
                sip_tar_path, updated_filename, sip_pcap_file
            );

            println!("Extracting SIP PCAP...");
            if Command::new("sh")
                .arg("-c")
                .arg(&sip_extract_command)
                .status()?
                .success()
            {
                println!("Moving SIP PCAP to merged directory...");
                fs::rename(&sip_pcap_file, &merged_pcap_file)?;
            } else {
                log_error(&format!(
                    "Failed to extract SIP PCAP for CDR ID: {}",
                    cdr_id
                ));
            }

            sip_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64() - sip_start;
        } else {
            if let Some(tar_positions) = &record.tar_positions {
                let rtp_start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();

                let xfvm_command = format!(
                    "--untar-gui={} {}.pcap {} {}",
                    rtp_tar_path,
                    filename,
                    String::from_utf8_lossy(tar_positions),
                    rtp_pcap_file
                );

                println!("Extracting RTP PCAP using XFVM...");
                if Command::new("xfvm")
                    .arg("-kc")
                    .arg(&xfvm_command)
                    .output()?
                    .status
                    .success()
                {
                    rtp_time =
                        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64() - rtp_start;

                    if Path::new(&rtp_pcap_file).exists() {
                        let metadata = fs::metadata(&rtp_pcap_file)?;
                        println!(
                            "RTP PCAP created successfully: {} (size: {} bytes)",
                            rtp_pcap_file,
                            metadata.len()
                        );

                        let sip_start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
                        let sip_extract_command = format!(
                            "tar --use-compress-program='pigz -p 4' --wildcards -xOf '{}' '{}.pcap*' > {}",
                            sip_tar_path, updated_filename, sip_pcap_file
                        );

                        println!("Extracting SIP PCAP...");
                        if Command::new("sh")
                            .arg("-c")
                            .arg(&sip_extract_command)
                            .status()?
                            .success()
                        {
                            sip_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64()
                                - sip_start;

                            if Path::new(&sip_pcap_file).exists() {
                                let metadata = fs::metadata(&sip_pcap_file)?;
                                println!(
                                    "SIP PCAP created successfully: {} (size: {} bytes)",
                                    sip_pcap_file,
                                    metadata.len()
                                );

                                let merge_start =
                                    SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
                                println!("Merging PCAPs...");

                                // Create empty output file
                                File::create(&merged_pcap_file)?;

                                let merge_output = Command::new("mergecap")
                                    .arg("-v")
                                    .arg("-w")
                                    .arg(&merged_pcap_file)
                                    .arg(&sip_pcap_file)
                                    .arg(&rtp_pcap_file)
                                    .output()?;

                                if merge_output.status.success() {
                                    merge_time =
                                        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64()
                                            - merge_start;
                                    println!("Successfully merged PCAPs to: {}", merged_pcap_file);
                                } else {
                                    let stderr = String::from_utf8_lossy(&merge_output.stderr);
                                    log_error(&format!(
                                        "Failed to merge PCAPs. Exit code: {:?}, Error: {}",
                                        merge_output.status.code(),
                                        stderr
                                    ));
                                }
                            }
                        } else {
                            log_error(&format!(
                                "Failed to extract SIP PCAP for CDR ID: {}",
                                cdr_id
                            ));
                        }
                    } else {
                        log_error(&format!("RTP PCAP file not created: {}", rtp_pcap_file));
                    }
                } else {
                    log_error(&format!(
                        "Failed to extract RTP PCAP for CDR ID: {}",
                        cdr_id
                    ));
                }
            }
        }

        // Clean up temporary files
        if Path::new(&sip_pcap_file).exists() {
            fs::remove_file(&sip_pcap_file)?;
        }
        if Path::new(&rtp_pcap_file).exists() {
            fs::remove_file(&rtp_pcap_file)?;
        }

        // Log performance metrics
        let total_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64() - record_start;
        writeln!(
            csv_file,
            "{},{},{},{},{},{}",
            cdr_id, db_time, rtp_time, sip_time, merge_time, total_time
        )?;

        log_perf(&format!("CDR {} - Complete", cdr_id), total_time);
    }

    let total_script_time =
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64() - script_start;
    log_perf("Total script execution", total_script_time);

    let records_per_second = num_records as f64 / total_script_time;
    println!(
        "Processed {} records at {:.2} records/second",
        num_records, records_per_second
    );

    Ok(())
}
