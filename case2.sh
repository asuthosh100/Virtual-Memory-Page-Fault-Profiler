#!/bin/bash

# Prompt the user to enter the value of N
read -p "Enter the number of processes (N): " N

# Validate the input
if ! [[ "$N" =~ ^[0-9]+$ ]]; then
    echo "Error: Please enter a valid integer for N."
    exit 1
fi

echo "Running experiment with N=$N processes..."

# Start N instances of the work process
for i in $(seq 1 $N); do
    nice ./work 200 RL 10000 &  # Start each process in the background
done

# Allow time for processes to run
echo "Waiting for processes to run..."
sleep 60  # Adjust the sleep time based on the duration needed

# Kill all background work processes (if they are still running)
echo "Terminating all work processes..."
pkill -f './work 200 RL 10000'

echo "Experiment completed!"
