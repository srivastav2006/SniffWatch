#!/bin/bash
# Docker run helper script for packet sniffer

echo "Starting Dockerized Packet Sniffer + IDS System..."

# Create necessary directories
mkdir -p logs captures

# Build the Docker image
echo "Building Docker image..."
docker-compose build

# Start all services
echo "Starting distributed monitoring services..."
docker-compose up -d

echo "Services started! Check logs with:"
echo "  docker-compose logs -f ids-collector"
echo "  docker-compose logs -f sniffer-node1"
echo ""
echo "Stop services with:"
echo "  docker-compose down"
echo ""
echo "View captured packets in ./captures/ directory"
echo "View alert logs in ./logs/ directory"
