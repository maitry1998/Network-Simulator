
#####################################################
# Developed by Maitry Chauhan & Sree Harsha for the course:
# DATA/COMPUTER COMMUNICATION
# Computer Science, FSU
#####################################################



1. How to run the code:

    Open different terminals and run:

    Bridges:
    python3 bridge.py cs1 8
    python3 bridge.py cs2 8
    python3 bridge.py cs3 8
    ---------------------------------------------------------------------------

    Routers:
    python3 station.py -route ./ifaces/ifaces.r1 ./rtables/rtable.r1 hosts
    python3 station.py -route ./ifaces/ifaces.r2 ./rtables/rtable.r2 hosts
    ---------------------------------------------------------------------------

    Stations:
    python3 station.py  -no ./ifaces/ifaces.a ./rtables/rtable.a hosts 
    python3 station.py  -no ./ifaces/ifaces.b ./rtables/rtable.b hosts 
    python3 station.py  -no ./ifaces/ifaces.c ./rtables/rtable.c hosts 
    python3 station.py  -no ./ifaces/ifaces.d ./rtables/rtable.d hosts 
    python3 station.py  -no ./ifaces/ifaces.e ./rtables/rtable.e hosts 
    ---------------------------------------------------------------------------

2.  Refrence Topology:

    
            B              C                D
            |              |                |
            cs1-----R1------cs2------R2-----cs3
            |              |                |
            -------A--------                E
    
    cs1, cs2, and cs3 are bridges.
    R1 and R2 are routers.
    A to E are hosts/stations.
    Note that A is multi-homed, but it is not a router.

3. Commands supported in stations/routers/bridges

   3.1 stations:

	   send <destination> <message> // send message to a destination host
	   show arp 		// show the ARP cache table information
	   show pq 		// show the pending_queue
	   show	host 		// show the IP/name mapping table
	   show	iface 		// show the interface information
	   show	rtable 		// show the contents of routing table
	   quit // close the station

   3.2 routers:

	   show	arp 		// show the ARP cache table information
	   show	pq 		// show the pending_queue
	   show	host 		// show the IP/name mapping table
	   show	iface 		// show the interface information
	   show	rtable 		// show the contents of routing table
	   quit // close the router


   3.3 bridges:

	   show sl 		// show the contents of self-learning table
	   quit // close the bridge


4. To start the emulation, run

   	run_simulation

   , which emulates the following network topology

   
          B              C                D
          |              |                |
         cs1-----R1------cs2------R2-----cs3
          |              |                |
          -------A--------                E




5. Difficulties that we have encountered during the development of the project

	1. implementing threaded timer for showing arp caches and self learning tables and keping track of when to update an entry and when to delete
    2. We started working on the retry mechanism at the end. This part became very challenging to implement at the end.
    3. Due to low buffer size our pending queues were not getting sent when a station reconnects after an indefinite shutdown.
    4. The most difficult part was dealing with stations that had multiple interfaces like station A

6. A LOG of the progress we make from time to time
	1. Implemented Bridge's connection with a single station liek server client.
    2. Implemented Bridge's connection with multiple station
    3. sent message from one station to other without any routers (D To E). Implemneted self learning table(fully working)
    4. Implemented a very basic ARP mechanism. Only brodcasting and getting reply.
    5. Now storing the arp responses and instead of brodcasting everytime.. fetching entry from arp cache.
    6. Sending data from a station to other with a router in between.
    6. Arp caching did not work when two routers are between stations. Fxed that.
    7. arp cache did not update for station A (multiple interfaces), Fixed that.
    8. Implementing timer for ARP cache. 
    9. Implementing timer for SL. 
    10. worked on pending queue. Only storing pending queue, not sending messages when a station reconnects.
    11. Implemneted the update timer when resends the message again funcanility.
    12. starrted working on the retry mechanism. 
    13. retry mechanism working for tations only.
    14. retry mechanism now working fro both station and routers.
    15. Fixed the pending quueue. (Realised that small buffer size and flooding the station were the reason why messaging were not getting populated on reconnection)
    16. removed unnecessary code like import sttamenets and variables and methods.
    17. started working on the report. Added some extra print debug stamenets to make the output more understandable. Beautified the messages. 

