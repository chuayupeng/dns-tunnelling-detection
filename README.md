# dns-tunnelling-detection
Attempt at utilising SVM One Class to classify and detect signs of DNS tunnelling

## Setup
1. Clone the directory
1. Enter the directory by typing in this command 

```cd dns-tunneling-detection```

1. Install prerequisite libraries with pip (if your OS does not have pip installed, try `sudo easy-install pip`

```pip install -r requirements.txt```

## Usage

Run the program with 3 parameters, the first two files to be used to train the model.

The first file will be your benign traffic packets, the second would be an example of dns tunneling.

The last file can be whatever you want to test the model against.

```python main.py pcap/good.pcap pcap/dns-tunnel-iodine.pcap pcap/population.pcap```

The program will write the flagged packets to a results.pcap file in the same directory.
