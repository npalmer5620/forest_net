# WSN ForestNet
The vast majority of the code is located in wsnlab/source/sensor_node.py which contains the SensorNode class that implements the WSN. The confiuration file allows modification of the network parameters to match 

# Instructions to Run the Code
There are several options available to run the code, note the code was developed with Python 3.13.9 and a venv is necessary.
- "python wsnlab/main.py" which runs the standard simulation that does not test any features such as
    killing nodes, changing topology, etc. All logs will be saved in the "logs" folder. They contain
    table data and path data for all non heartbeat or probe packets sent.
- "python wsnlab/main_delete_node.py" deletes a configurable number of nodes at random and tests the ability for the
    network to heal and remap.


#
