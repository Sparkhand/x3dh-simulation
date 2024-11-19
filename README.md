# Signal  protocol (X3DH)

## How to run the code

This small project is designed to didattically simulate [X3DH (Extended Triple Diffie-Hellman)](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange#Triple_Diffie%E2%80%93Hellman_(3-DH)) protocol between Alice and Bob. It is all done via Docker, so you need to have it installed on your system.

Within the file `tripleDH.env` you can configure some environment variables that will be visible to the two containers:
- `PRIME_NUMBER_BITS` is the number of bits of the prime number that will be generated as a Diffie-Hellman parameter (p)
- `KEY_BITS` is the number of bits of the private key that will be generated for Alice and Bob
- `MESSAGE_TO_SEND` is the message that Alice will send to Bob
- `VERBOSE` is a flag that allows a richer output to be displayed during the simulation
- `ATTACH` is a flag that allows access to the container terminal.

More specifically, there are two ways in which you can run the simulation, we'll call them “AUTOMATIC” and “INTERACTIVE”

### AUTOMATIC

This mode leaves the execution of code to Docker, without human intervention.

To run the simulation in “automatic” mode, you must set the `ATTACH` environment variable to `0`.

Then, run the command:

```bash
docker compose up --build
```

which will take care of creating and starting the two containers and executing the code automatically. The output of both containers will be visible on the terminal.

In case you want to view the output of Alice and Bob separately, you can run the commands:

```bash
docker compose logs -f alice
docker compose logs -f bob
```

### INTERACTIVE

This mode requires human intervention which involves pressing the `Enter` key to advance in the simulation, sometimes on Alice's side and sometimes on Bob's side. Thanks to this mode, the various steps of the simulation are more appreciable.

In this case it is necessary to set `ATTACH=1`. It is strongly recommended to also set `VERBOSE=1` to have a more detailed and “engaging” output.

Next, run the command:

```bash
docker compose up -d --build
```
(note the `-d` option for detached mode). At this point the containers are running but are not yet executing code.

**Open two terminals, put them next to each other** and run:

```bash
docker exec -en bob python -u bob.py
```

in the first one and

```bash
docker exec -en bob python -u alice.py
```

in the second one. **It is important that Bob is started before Alice as it acts as a “server” and waits for Alice's connection**.
