
# Dockerized Packet Sniffer + Basic IDS

A containerized, distributed **packet sniffer** and **IDS** system using **Docker** and **Scapy**. 
Features multiple sniffer nodes with centralized alert collection for scalable network monitoring.

## Features
- **Dockerized Architecture**: Portable containers that run on any Docker-enabled system
- **Distributed Monitoring**: Multiple sniffer nodes with centralized IDS collector
- **Docker Compose**: Easy multi-container orchestration
- **Persistent Storage**: Captures and logs saved to host volumes
- **Network Isolation**: Custom Docker network for secure inter-container communication

## Quick Start

### 1) Build and Start
Make run script executable
`chmod +x docker-run.sh`

Start the entire system
`./docker-run.sh`



### 2) Manual Docker Compose
Build images
`docker-compose build`

Start distributed monitoring
`docker-compose up -d`

View logs
`docker-compose logs -f ids-collector`
`docker-compose logs -f sniffer-node1`



### 3) Individual Container Usage
Run standalone sniffer
`docker run --rm -it --cap-add=NET_ADMIN --cap-add=NET_RAW
-v $(pwd)/captures:/app/captures
packet-sniffer python sniffer.py -i eth0`

Run IDS
`docker run --rm -it --cap-add=NET_ADMIN --cap-add=NET_RAW
-v $(pwd)/logs:/app/logs
packet-sniffer python sniffer_ids.py -i eth0`



## Docker Architecture

### Services
- **ids-collector**: Central IDS node for threat detection
- **sniffer-node1/2/3**: Distributed packet capture nodes
- **monitoring-network**: Isolated Docker bridge network

### Volumes
- `./captures`: Packet capture files (.pcap)
- `./logs`: Alert logs (JSON format)

### Network Requirements
- Containers need `NET_ADMIN` and `NET_RAW` capabilities
- Privileged mode for raw socket access
- Custom bridge network (172.20.0.0/16)

## File Structure
packet-sniffer/
├── Dockerfile # Container build instructions
├── docker-compose.yml # Multi-container orchestration
├── docker-run.sh # Helper startup script
├── sniffer.py # Enhanced Scapy sniffer
├── sniffer_ids.py # Enhanced IDS with logging
├── requirements.txt # Python dependencies
├── .dockerignore # Docker build exclusions
├── captures/ # Volume for .pcap files
├── logs/ # Volume for alert logs
└── README.md # This file


## Monitoring

### View Real-time Alerts
Watch IDS alerts
`docker-compose logs -f ids-collector`

Watch specific node
`docker-compose logs -f sniffer-node1`


### Access Captured Data
List captured packets
`ls -la captures/`

View alert logs
`cat logs/alerts_collector.json | jq .`



## Scaling

### Add More Nodes
Edit `docker-compose.yml` to add additional sniffer nodes:

sniffer-node4:
build: .
container_name: sniffer-node4
command: `python sniffer.py -i eth0 --pcap /app/captures/node4.pcap -q`

... rest of configuration


### Horizontal Scaling
Scale sniffer nodes
`docker-compose up --scale sniffer-node1=3 -d`



## Cleanup
Stop all containers
`docker-compose down`

Remove volumes (CAUTION: deletes captured data)
`docker-compose down -v`

Remove images
`docker rmi packet-sniffer_ids-collector`


Complete File Structure

packet-sniffer/
├── Dockerfile
├── docker-compose.yml
├── docker-run.sh
├── sniffer.py
├── sniffer_ids.py
├── requirements.txt
├── .dockerignore
├── README.md
├── captures/          # Created automatically
└── logs/             # Created automatically
File Locations and Usage
Root Directory: /packet-sniffer/

Dockerfile: /packet-sniffer/Dockerfile

Compose File: /packet-sniffer/docker-compose.yml

Main Scripts: /packet-sniffer/sniffer.py, /packet-sniffer/sniffer_ids.py

Helper Script: /packet-sniffer/docker-run.sh

Dependencies: /packet-sniffer/requirements.txt

Docker Ignore: /packet-sniffer/.dockerignore

Documentation: /packet-sniffer/README.md

