#!/bin/bash

# Check if ATTACH environment variable is set
if [ -z "$ATTACH" ]; then
    ATTACH=0
fi

if [ "$ATTACH" = "1" ]; then
    exec /bin/bash
else
    # Check which service is running (alice or bob)
    if [ "$SERVICE_NAME" = "alice" ]; then
        echo "Starting Alice..."
        exec python -u alice.py
    elif [ "$SERVICE_NAME" = "bob" ]; then
        echo "Starting Bob..."
        exec python -u bob.py
    else
        echo "ERROR! Unknown service name: $SERVICE_NAME"
        exit 1
    fi
fi
