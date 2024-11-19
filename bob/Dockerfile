FROM python:3.9-slim

WORKDIR /app

# Copy Bob's script, libraries and entrypoint
COPY ./shared /app/shared
COPY bob/bob.py /app/bob.py
COPY ./entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh
RUN pip install pycryptodome

# Run the entrypoint
ENTRYPOINT ["/entrypoint.sh"]
