#!/bin/bash

# Function to print usage
usage() {
    echo "Usage: $0 -f <file> [-p <password>]"
    echo "Supported file types: .pfx, .pem, .csr, .key"
    exit 1
}

# Function to check weak algorithms
check_weak_algo() {
    local algo=$1
    local weak_algos=("md2" "md4" "md5" "sha1" "sha1WithRSAEncryption" "ecdsa-with-SHA1" "DSA-SHA1" "RC4")

    for weak_algo in "${weak_algos[@]}"; do
        if [[ "$algo" == *"$weak_algo"* ]]; then
            echo "Warning: Algorithm uses $weak_algo, which is considered weak."
            return
        fi
    done
}

# Function to check certificate details
check_cert() {
    local cert_file=$1

    echo "Checking Certificate: $cert_file"
    
    # Check for certificate validity
    cert_validity=$(openssl x509 -in "$cert_file" -noout -dates 2>/dev/null)
    echo "Certificate Validity:"
    echo "$cert_validity"
    echo ""

    # Check for key length (if applicable)
    key_length=$(openssl x509 -noout -modulus -in "$cert_file" 2>/dev/null | openssl rsa -noout -text 2>/dev/null | grep "Private-Key" | awk '{print $2}')
    if [ -n "$key_length" ]; then
        echo "Key Length: $key_length bits"
        if [ "$key_length" -lt 2048 ]; then
            echo "Warning: Key length is less than 2048 bits!"
        fi
    else
        echo "Failed to determine key length."
    fi
    echo ""

    # Check for weak hashing and signature algorithms
    signature_algo=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep "Signature Algorithm" | awk -F ': ' '{print $2}')
    echo "Signature Algorithm: $signature_algo"
    check_weak_algo "$signature_algo"
    echo ""

    # Check certificate chain (if applicable)
    chain_validity=$(openssl verify -CAfile "$cert_file" "$cert_file" 2>/dev/null)
    echo "Certificate Chain Validity:"
    echo "$chain_validity"
    echo ""
}

# Function to check private key details
check_key() {
    local key_file=$1

    echo "Checking Private Key: $key_file"

    # Check for key length
    key_length=$(openssl rsa -in "$key_file" -noout -text 2>/dev/null | grep "Private-Key" | awk '{print $2}')
    if [ -n "$key_length" ]; then
        echo "Key Length: $key_length bits"
        if [ "$key_length" -lt 2048 ]; then
            echo "Warning: Key length is less than 2048 bits!"
        fi
    else
        echo "Failed to determine key length."
    fi
    echo ""

    # Check private key encryption
    if openssl rsa -in "$key_file" -text -noout 2>&1 | grep -q "ENCRYPTED"; then
        echo "Private Key is encrypted."
    else
        echo "Warning: Private Key is not encrypted."
    fi
    echo ""
}

# Function to check CSR details
check_csr() {
    local csr_file=$1

    echo "Checking CSR: $csr_file"

    # Check for key length
    key_length=$(openssl req -in "$csr_file" -noout -text 2>/dev/null | grep "Public-Key" | awk '{print $2}')
    if [ -n "$key_length" ]; then
        echo "Key Length: $key_length bits"
        if [ "$key_length" -lt 2048 ]; then
            echo "Warning: Key length is less than 2048 bits!"
        fi
    else
        echo "Failed to determine key length."
    fi
    echo ""

    # Check for weak hashing and signature algorithms
    signature_algo=$(openssl req -in "$csr_file" -noout -text 2>/dev/null | grep "Signature Algorithm" | awk -F ': ' '{print $2}')
    echo "Signature Algorithm: $signature_algo"
    check_weak_algo "$signature_algo"
    echo ""
}

# Function to check PFX file
check_pfx() {
    local pfx_file=$1
    local password=$2

    echo "Checking PFX File: $pfx_file"
    
    # Check MAC algorithm without password
    mac_algo=$(openssl pkcs12 -info -in "$pfx_file" -noout -passin pass:dummy 2>&1 | grep "MAC: " | awk -F ': ' '{print $2}' | awk '{print $1}')
    echo "MAC Algorithm: $mac_algo"
    check_weak_algo "$mac_algo"
    echo ""

    if [ -n "$password" ]; then
        # Temporary file for extraction
        cert_file=$(mktemp)

        # Extract certificate and private key
        if openssl pkcs12 -in "$pfx_file" -out "$cert_file" -nodes -passin pass:"$password" > /dev/null 2>&1; then
            check_cert "$cert_file"

            # Check private key encryption
            if openssl pkcs12 -in "$pfx_file" -nodes -passin pass:"$password" 2>/dev/null | grep -q "Proc-Type: 4,ENCRYPTED"; then
                echo "Private Key is encrypted."
            else
                echo "Warning: Private Key is not encrypted."
            fi
            echo ""

            # Clean up temporary file
            rm -f "$cert_file"
        else
            echo "Failed to extract certificate and private key from $pfx_file"
            exit 1
        fi
    fi
}

# Parse command line arguments
while getopts ":f:p:" opt; do
    case $opt in
        f) file="$OPTARG"
        ;;
        p) password="$OPTARG"
        ;;
        \?) echo "Invalid option -$OPTARG" >&2
            usage
        ;;
        :) echo "Option -$OPTARG requires an argument." >&2
            usage
        ;;
    esac
done

# Check if the necessary arguments are provided
if [ -z "$file" ]; then
    usage
fi

# Determine the file type and perform appropriate checks
case "$file" in
    *.pfx)
        check_pfx "$file" "$password"
        ;;
    *.pem)
        if openssl x509 -noout -in "$file" &>/dev/null; then
            check_cert "$file"
        elif openssl rsa -noout -in "$file" &>/dev/null; then
            check_key "$file"
        else
            echo "Unsupported .pem file format."
            exit 1
        fi
        ;;
    *.csr)
        check_csr "$file"
        ;;
    *.key)
        check_key "$file"
        ;;
    *)
        echo "Unsupported file type."
        usage
        ;;
esac

echo "File check completed."
