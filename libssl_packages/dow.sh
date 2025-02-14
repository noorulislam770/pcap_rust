#!/bin/bash

# Create a directory for the packages
mkdir -p ssl_packages
cd ssl_packages

# Download main packages and dependencies
wget http://ftp.debian.org/debian/pool/main/o/openssl/libssl3_3.0.11-1~deb12u2_amd64.deb
wget http://ftp.debian.org/debian/pool/main/o/openssl/libssl-dev_3.0.11-1~deb12u2_amd64.deb
wget http://ftp.debian.org/debian/pool/main/o/openssl/openssl_3.0.11-1~deb12u2_amd64.deb
wget http://ftp.debian.org/debian/pool/main/d/debconf/debconf_1.5.82_all.deb
wget http://ftp.debian.org/debian/pool/main/p/perl/perl-base_5.36.0-7+deb12u1_amd64.deb
wget http://ftp.debian.org/debian/pool/main/p/perl/perl_5.36.0-7+deb12u1_amd64.deb
wget http://ftp.debian.org/debian/pool/main/p/perl/libperl5.36_5.36.0-7+deb12u1_amd64.deb
wget http://ftp.debian.org/debian/pool/main/z/zlib/zlib1g_1.2.13.dfsg-1_amd64.deb
wget http://ftp.debian.org/debian/pool/main/z/zlib/zlib1g-dev_1.2.13.dfsg-1_amd64.deb

# Create a tar archive of all downloaded packages
tar czf ssl_packages.tar.gz *.deb

# Print instructions
echo "Downloads completed. Transfer ssl_packages.tar.gz to your Debian machine."
echo "Then run these commands on the Debian machine:"
echo "tar xzf ssl_packages.tar.gz"
echo "sudo dpkg -i *.deb"
