FROM ubuntu

WORKDIR /app
COPY requirements.txt .
RUN apt update && \
    apt install -y python3 python3-pip qemu-user && \
    pip install -r requirements.txt --break-system-packages
