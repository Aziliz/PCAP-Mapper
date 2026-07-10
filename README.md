# PCAP-Mapper

How I've been building:
1. Unzip the pcap directory
2. cd into to pcap mapper directory
3. docker system prune (clear out old saved docker file)
4. docker build -t pcap-mapper .
5. docker run --rm --name pcap-mapper -p 8000:8000 -v "$PWD/uploads:/app/uploads:Z" -v "$PWD/results:/app/results:Z" --memory=8g pcap-mapper

Feel free to test and let me know if any features are requested.
