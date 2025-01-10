#!/bin/bash

# Directory containing input subfolders
INPUT_DIR="../captures/comm_patterns"

# Directory for output subfolders
OUTPUT_DIR="outputs"

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Loop through subfolders in the input directory that start with "mpi", "tree", "ring" or "init"
for subfolder in "$INPUT_DIR"/{mpi,tree,ring,init}*; do
    # Skip if not a directory
    if [[ ! -d "$subfolder" ]]; then
        continue
    fi

    # Get the base name of the subfolder (without the parent directory)
    subfolder_name=$(basename "$subfolder")

    # Create a corresponding subfolder in the output directory
    output_subfolder="$OUTPUT_DIR/$subfolder_name"
    mkdir -p "$output_subfolder"

    # Loop through all .pcap files in the current subfolder
    for pcap_file in "$subfolder"/*.pcap; do
        # Get the base name of the .pcap file (without directory and extension)
        base_name=$(basename "$pcap_file" .pcap)

        # Construct the output file names for layer3 and layer4
        output_file_layer3="$output_subfolder/${base_name}_3.png"
        output_file_layer4="$output_subfolder/${base_name}_4.png"

        # Run the Python command for layer3
        python3 main.py -i "$pcap_file" -o "$output_file_layer3" --layer3 -E dot -s ellipse --message-detail full
        python3 main.py -i "$pcap_file" -o "$output_file_layer3" --layer3 -E dot -s ellipse --message-detail summary

        # Run the Python command for layer
        python3 main.py -i "$pcap_file" -o "$output_file_layer4" --layer4 -E dot -s ellipse --message-detail full
        python3 main.py -i "$pcap_file" -o "$output_file_layer4" --layer4 -E dot -s ellipse --message-detail summary
    done
done
