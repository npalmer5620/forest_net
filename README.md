# WSN ForestNet
The vast majority of the code is located in wsnlab/source/sensor_node.py which contains the SensorNode class that implements the WSN. The confiuration file "wsnlab/source/config.py" allows modification of the network parameters and test various things.

# Featureset
- PROBE and HEARTBEAT packets to advertise capabilities and roles, populate negihbor tables and allows nodes to test if neighbors are alive.
- Hybrid routing protocol, n-hop mesh with AODV type (ROUTE REQ, ROUTE RESP) to discovery 2 hop neighbors. Note: that > 1 hop does not function correctly, I focused on getting tree routing working properly and using local mesh inbetween.
- Tree routing is functional, Cluster Heads learn routes via NETID_REQ and NETID_RESP packets and stores this info in child networks tables.
- Routers exist as bridges between pairs of Cluster Heads, witout the additional metadata and overhead of maintaining members and child networks tables. A Cluster Head will see if any of its members can be promoted to CH and if we can promote to a router. 

# Instructions to Run the Code
There are several options available to run the code, note the code was developed with Python 3.13.9 and a venv is probably necessary.
- "python wsnlab/main.py" which runs the standard simulation that does not test any features such as
    killing nodes, changing topology, etc. All logs will be saved in the "logs" folder. They contain table data and path data for all non heartbeat or probe packets sent.
- "python wsnlab/main_delete_node.py" deletes a configurable number of nodes at random and tests the ability for the network to heal and remap.


#
