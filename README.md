# Mitre Heat Map PCAP-Mapper

This is a program to automate mapping pcaps to the Mitre Navigatior/Att&ck. Currently supports Mitre Stix v13-v19 with v18 being default. Has basic analysis tools, and is mainly used for creating Mitre heat maps. There's multiple methods of analysis added, by default it's based off Mitre Stix, but also includes heuristic analysis.

# Technicial Notes
Those program was purposly made with limited python libraries.

-Python
-Flask
-Scapy

I've also included a simulated linux and windows test pcap environment to verify functionality.

# Build

How I've been building:
1. Unzip the pcap directory
2. cd into to pcap mapper directory
3. docker build -t pcap-mapper .
4. docker run --rm --name pcap-mapper -p 8000:8000 -v "$PWD/uploads:/app/uploads:Z" -v "$PWD/results:/app/results:Z" --memory=8g pcap-mapper

Feel free to test and let me know if any features are requested.

# Program Basics

The program runs on a job basis so that you can compare multiple networks at the same time. You can also upload additional pcaps to the job for a broader scope of coverage over time. Has a basic Asset, Communication, Log Sources, and Event Pages for Analysts to use.

Asset Page
<img width="3089" height="631" alt="Screenshot From 2026-07-15 11-47-59" src="https://github.com/user-attachments/assets/16dea390-f809-4ee6-9ee9-86ca52f50463" />

Communication/Flow Page
<img width="3074" height="1364" alt="Screenshot From 2026-07-15 11-48-33" src="https://github.com/user-attachments/assets/b704e5b7-7a38-4a67-84ec-c2e457423695" />

Log Sources Page
<img width="3074" height="1364" alt="Screenshot From 2026-07-15 11-54-40" src="https://github.com/user-attachments/assets/225be9ac-cf95-4348-b7ec-70842fbb4ad4" />

Event Page
<img width="3074" height="1364" alt="Screenshot From 2026-07-15 11-50-40" src="https://github.com/user-attachments/assets/dc1c4d40-64b5-49c0-9dd5-f7173893767b" />

The validated section in the heatmap are based off the predefined and user generated rules, and shows what flows directly map to techniques.
<img width="3074" height="1364" alt="Screenshot From 2026-07-15 11-52-35" src="https://github.com/user-attachments/assets/d00f6f6b-0e7d-4aaa-953b-f78906437d36" />

There's also telemetry plugin page which includes 186 plugins by default and the ability to map more, for a greater confidence in theoretical coverage.
<img width="3074" height="1364" alt="Screenshot From 2026-07-15 11-54-11" src="https://github.com/user-attachments/assets/fbab6857-6fc7-431b-905a-45a6c49caf97" />


# Heatmap viewing

You can view an enterprise wide view of coverage from within the app.

<img width="3126" height="1548" alt="Screenshot From 2026-07-15 11-39-11" src="https://github.com/user-attachments/assets/8fdf0454-69f3-43af-8dc7-30e461316776" />

Click on observable threat boxes to get what log event triggered the mapping.

<img width="3126" height="1548" alt="Screenshot From 2026-07-15 11-39-45" src="https://github.com/user-attachments/assets/0c7336b1-b9fa-43c7-afbb-d4e61d55573d" />

Also export the mapping to the Mitre Attack Navigator for a comprehensive view.

<img width="3126" height="1548" alt="Screenshot From 2026-07-15 11-34-45" src="https://github.com/user-attachments/assets/d2242ee8-1e4e-440d-822d-59f60b9722c8" />

Red shows clearly defined threats based off of PCAP information.
Yellow shows possible threats but analysts are needed to verify false positives.
Green shows a theoretical network coverage, based on telemetry, to map logs to multiple attack types. Shows possible attacks based off of correlated log types.
