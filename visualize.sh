#!/bin/bash

# Directory containing input .pcap files
INPUT_DIR="../captures"

# Directory for output .png files
OUTPUT_DIR="outputs"

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Loop through all .pcap files in the input directory
for pcap_file in "$INPUT_DIR"/*.pcap; do
    # Get the base name of the file (without directory and extension)
    base_name=$(basename "$pcap_file" .pcap)
    
    # Construct the output file names for layer3 and layer4
    output_file_layer3="$OUTPUT_DIR/${base_name}_3.png"
    output_file_layer4="$OUTPUT_DIR/${base_name}_4.png"
    
    # Run the Python command for layer3
    python3 main.py -i "$pcap_file" -o "$output_file_layer3" --layer3 -E dot -s ellipse
    
    # Run the Python command for layer4
    python3 main.py -i "$pcap_file" -o "$output_file_layer4" --layer4 -E dot -s ellipse
done
