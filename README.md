# dns-tunnelling-detection
Attempt at utilising SVM One Class to classify and detect signs of DNS tunnelling

## Setup
1. Clone the directory
1. Enter the directory by typing in this command 

```cd dns-tunneling-detection```

1. Install prerequisite libraries with pip (if your OS does not have pip installed, try `sudo easy-install pip`

```pip install -r requirements.txt```

## Usage

There are two ways to run the program, one with labelled training data and one without.

### Running with good.pcap and bad.pcap files

Run the program with 3 parameters, the first two files to be used to train the model.

The first file will be your benign traffic packets, the second would be an example of dns tunneling.

The last file can be whatever you want to test the model against.

Command:

```python main.py pcap/good.pcap pcap/bad.pcap pcap/population.pcap```

### Running just against the test file to check for outliers

Run the program with one parameter, the pcap file you want to test against.

Command: 


```python main.py pcap/population.pcap```

In both cases, the program will write the flagged packets to a results.pcap file in the same directory.

Example:

![Screenshot](https://raw.githubusercontent.com/chuayupeng/dns-tunnelling-detection/master/usageImg.png)
