#!/bin/bash
#
# Convenience script to run the Atlas IP Access Analyzer
# Sources .env file if it exists, then runs the Python script

set -e

# Check if .env file exists and source it
if [ -f ".env" ]; then
    echo "Loading credentials from .env file..."
    source .env
else
    echo "Warning: .env file not found. Using environment variables or command-line arguments."
fi

# Run the Python script
python atlas_ip_access_analyzer.py "$@"
