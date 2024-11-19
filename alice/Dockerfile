FROM python:3.9-slim

WORKDIR /app

# Copy Alice's script, libraries and entrypoint
COPY ./shared /app/shared
COPY alice/alice.py /app/alice.py
COPY ./entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh
RUN pip install pycryptodome

# Run the entrypoint
ENTRYPOINT ["/entrypoint.sh"]
