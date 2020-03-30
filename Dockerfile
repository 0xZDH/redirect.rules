# Build:
#   docker build --tag=redirect_rules .
#
# Run:
#   docker run --rm -v $(pwd):/tmp redirect_rules -d <REDIRECT_DOMAIN>
#
# Run with an exclude file:
#   docker cp exclude.txt <CONTAINER>:/app/exclude.txt
#   docker run --rm -v $(pwd):/tmp redirect_rules -d <REDIRECT_DOMAIN> --exclude-file exclude.txt

# Reference: https://github.com/0xdade/sephiroth/blob/master/Dockerfile

FROM python:3.8.1-buster

LABEL gitrepo="https://github.com/0xZDH/redirect.rules"

# Update the system
RUN apt-get update

# Install Whois tool
RUN apt-get install -y whois

# Clean up
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Initialize a working directory
WORKDIR /app
COPY . .

# Install Python requirements
RUN pip install --no-cache-dir -r requirements.txt

# Make the file executable
RUN chmod +x redirect_rules.py && \
    sed -i 's/\r//' redirect_rules.py

# Share volume /tmp where we will write the
# redirect.rules files
VOLUME /tmp

ENTRYPOINT [ "./redirect_rules.py"]