"""
    Packet Sniffer - sniff network packets in and out of a machine and generate statistics
    Intended to run on Python 3.x

    Team 1 ( Team Leopard Gecko )
    -----------------------------
    -Joel De La Cruz
    -Joel Issman
    -Megan Henson
    -Michael Swindon
    -Andre DeLellis


    This program uses winpcapy, a wrapper for WinPcap (Windows) or libpcap (unix)
        download:      https://code.google.com/p/winpcapy/
        
        download:      https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe
                       http://www.tcpdump.org/#latest-release
                       
        documentation: https://www.winpcap.org/docs/
        
    
    This program uses ttk, a wrapper for tkinter
        download:      http://svn.python.org/view/*checkout*/sandbox/trunk/ttk-gsoc/src/3.x/ttk.py?revision=69049
        documentation: https://docs.python.org/3.4/library/tkinter.ttk.html

    Last modified 11/10/2015
"""

import ipaddress
import os
from tkinter import *
from tkinter import messagebox

import ttk
from protocols import protocols

try:
    from packetSniffer import *
except Exception as e:
    root = Tk()
    root.withdraw()
    messagebox.showerror("Error", "Error: " + str(e))
    raise ImportError

    

### Util fuctions
###############################################################################

# 192.168.1.1
def decodeIPv4(ipList):
    return ".".join(str(x) for x in ipList)


# 2001:fe80:d89::48
def decodeIPv6(ipList):
    hex = ""

    for i in range(0, 16, 2):
        # Convert to hex in groups of two, append a colon
        block = "{:02x}{:02x}:".format(ipList[i], ipList[i + 1])
        hex += block

    # Remove trailing colon
    hex = hex[:-1]

    ip = ipaddress.ip_address(hex)
    return ip.compressed


# Converts a packet sequence ID (32 bits) to a color
# Formula is (x >> 18)^2 % (2^24)
def numberToColorCode(number):
    result = number >> 18  # Ignore small changes
    result = pow(result, 2, pow(2, 24))  # Square number to add deviation to bigger differences
    result = "{:06x}".format(result)
    result = result.upper()

    return result


    
## UI functions
###############################################################################


# Create a popup window showing the user the payload of a packet
# Triggers when the user double-clicks on a row in the main table
# Row is passed as the click event coords
def viewPayload(sniffer, event):
    widgets = sniffer.graphicsHandle[1]#Set widget

    item = widgets["table"].identify("item", event.x, event.y)#Gathers click area for row
    packetID = widgets["table"].item(item, "values")#Gathers packetID where clicked

    try:
        packetID = packetID[0]#Check if user clicked a row by seeing if the packet ID worked
    except:
        # User clicked somewhere on the table that isn't a row, do not continue function
        return

    packetID = int(packetID)#Set packetID.


    popup = Toplevel()#Create Window
    popup.title("Viewing packet #" + str(packetID) + " payload")#Populate Title
    popup.geometry("400x400")#Set Window Dimensions

    dir = os.path.dirname(os.path.abspath(__file__))#Set directory path for icon
    # Icon is placed at top left of popup aswell.
    #It isn't worth it to stop execution over the icon
    try:#Try to set the icon.
        popup.iconbitmap(dir + os.sep + "favicon.ico")
    except:#Fail silenty if we encounter an error here.
        pass

    # Scrollbar for the text
    scrollbar = Scrollbar(popup)#Adds scrollbar by Tkinter onto the popup
    scrollbar.pack(side=RIGHT, fill=Y)#Sets scrollbar location and fills it all the way down top to bottom


    payloadText = Text(popup, yscrollcommand=scrollbar.set)#Links scrollbar to text node(the popup)
    # Fill text node(the popup)
    payloadText.insert(1.0, sniffer.payloads[packetID - 1])#Insert payload information based off packetID
    payloadText.pack(side=LEFT, fill=BOTH, anchor=N)
    payloadText.config(state="disabled")

    scrollbar.config(command=payloadText.yview)

    # Loop the popup and return
    popup.mainloop()


# Color-codes rows by their TCP sequence ID
#  Generates and adjusts the text color so that it's more easily readable
def addRowColor(table, tag):#This function adds the following
    rowColor = numberToColorCode(tag)#This is function that returns the rowColow value, it is seen below

    r, g, b = rowColor[:2], rowColor[2:4], rowColor[4:]
    r, g, b = [int(n, 16) for n in (r, g, b)]

    luminousity = (r * 0.299) + (g * 0.587) + (b * 0.114)#Formula for how bright the row color is

    if luminousity > 150:#If row color is too bright
        textColor = "#000"#Set text to black
    else:#Else if rowColor is too bright
        textColor = "#FFF"#Set text to white

    table.tag_configure(rowColor, background="#" + rowColor, foreground=textColor)
    return rowColor


# Toggle capturing packets, linked to a UI button
def toggleCapturing(sniffer):
    widgets = sniffer.graphicsHandle[1]

    # Sniffer isn't running, start it
    if not sniffer.isCapturing:
        widgets["toggleCapturingButton"].config(text="Stop capture")
        widgets["adapterSelector"].config(state="disabled")

        selectedAdapter = widgets["vars"]["adapter"].get()
        numAdapters = len(sniffer.adapters)

        for num in range(numAdapters):
            if sniffer.adapters[num]["description"] == selectedAdapter:
                adapterName = sniffer.adapters[num]["name"]
                sniffer.ip4 = sniffer.adapters[num]["ipv4"]
                sniffer.ip6 = sniffer.adapters[num]["ipv6"]

        sniffer.listenAdapter(adapterName)
        sniffer.start()

    # Sniffer is running, stop it
    else:
        widgets["toggleCapturingButton"].config(text="Start capturing")
        widgets["adapterSelector"].config(state="normal")
        sniffer.stop()
        



# Clears all data in all the fields in the UI, this function is called by the button code I presented in the image above.
def clearData(sniffer):
    widgets = sniffer.graphicsHandle[1]
    
    widgets["topTen"].delete(*widgets["topTen"].get_children())
    widgets["table"].delete(*widgets["table"].get_children())
    widgets["commonData"].delete(*widgets["commonData"].get_children())
    
    sniffer.packetsIn  = 0
    sniffer.packetsOut = 0
    sniffer.numPackets = 0

    sniffer.topDestinations = {}
    sniffer.commonData = [""]
    sniffer.payloads = []
    
    widgets["packetsIn"].config(text="Packets in: 0")
    widgets["packetsOut"].config(text="Packets out: 0")


# Finally this lays out the graphics interface
def initGraphicsWindow(sniffer):
    WINDOW_TITLE = "Packet Sniffer for Kirk Suscella"#Title at top-left of program's window
    WINDOW_ICON  = "favicon.ico" #Icon image at top left of window

    adapterNames = (ad["description"] for ad in sniffer.adapters)#Adds adapter name to var
    root = Tk()#Essential for using Tkinter module
    root.wm_title(WINDOW_TITLE)#Runs the title through Tkinter so it's used.
    root.protocol("WM_DELETE_WINDOW", lambda: exitprogram(sniffer))

    # http://stackoverflow.com/questions/3430372/how-to-get-full-path-of-current-files-directory-in-python
    dir = os.path.dirname(os.path.abspath(__file__))
    
    # Try to set the icon, fail silenty if we encounter an error here. It isn't worth it to stop execution over the icon
    try:
        root.iconbitmap(dir + os.sep + WINDOW_ICON)
    except:
        pass

    widgets = {
        "vars": {}
    }

    root.resizable(0, 0)

    # Text label
    Label(root, text="Select an adapter:").grid(row=0, column=0, sticky="e", pady=5)
    Label(root, text="Filter Protocol:").grid(row=1, column=0, sticky="e", pady=5)
        
    # Start / Pause button
    widgets["toggleCapturingButton"] = Button(
        text="Start capture",
        command=lambda: toggleCapturing(sniffer),
        state="disabled"
    )

    widgets["toggleCapturingButton"].grid(row=0, column=2, pady=5, sticky="e")
    
    # Clear button
    widgets["clearButton"] = Button(
        text="Clear",
        command=lambda: clearData(sniffer)
    )
    
    widgets["clearButton"].grid(row=0, column=3, pady=5)
    #protocol selector
    widgets["vars"]["protocol"] = StringVar(root)#Sets Widget Section and use
    widgets["protocolFilter"] = Entry(root)#Entry Box
    widgets["protocolFilter"].grid(row=1, column=1)#Sets the position of it
   
    sniffer.filterEnabled = IntVar()
    widgets["toggleFilterBox"] = Checkbutton(#Check Button that allows you to enable the filter
        root,
        text = "Use Filter",
        variable = sniffer.filterEnabled,
        onvalue = True,
        offvalue = False
    )
    widgets["toggleFilterBox"].grid(row=1, column=2, pady=5)
    # Selector
    widgets["vars"]["adapter"] = StringVar(root)
    widgets["adapterSelector"] = OptionMenu(root, widgets["vars"]["adapter"], *adapterNames,
                                            command=lambda d: widgets["toggleCapturingButton"].config(state="normal"))
    widgets["adapterSelector"].grid(row=0, column=1, sticky="e", pady=5)

    # Separator
    ttk.Separator(root).grid(row=2, column=0, columnspan=5, sticky="ew", pady=5)

    # Packet stats
    widgets["packetsIn"] = Label(root, text="Packets in:  0")#Label for packets incoming
    widgets["packetsOut"] = Label(root, text="Packets out: 0")#Label for packets outgoing
    widgets["packetsIn"].grid(row=2, column=0, columnspan=2, pady=5)#Sets position for label of packets incoming
    widgets["packetsOut"].grid(row=2, column=2, columnspan=2, pady=5)#Sets position for label of packets outgoing

    # Main table
    widgets["table"] = ttk.Treeview(root, height=15)
    widgets["table"]["show"] = "headings"
    widgets["table"]["columns"] = (
    "Number", "Timestamp", "Source", "Destination", "Direction", "Payload size", "Protocol", "TCP Sequence #")

    for columnName in widgets["table"]["columns"]:
        widgets["table"].column(columnName, width=100, anchor="e")
        widgets["table"].heading(columnName, text=columnName)

    widgets["table"].bind("<Double-1>", lambda e: viewPayload(sniffer, e))
    widgets["table"].grid(row=3, columnspan=4, sticky="e")

    # Table scrollbar
    scrollbar = Scrollbar(root)
    scrollbar.grid(row=3, column=4, sticky="ns")

    scrollbar.config(command=widgets["table"].yview)
    widgets["table"].config(yscrollcommand=scrollbar.set)

    # Other labels
    Label(root, text="Top ten destinations:", width=50).grid(row=4, column=0, columnspan=2, pady=5)
    Label(root, text="Extracted common data:", width=50).grid(row=4, column=2, columnspan=2, pady=5)

    # Top Ten table
    widgets["topTen"] = ttk.Treeview(root, height=10)
    widgets["topTen"]["show"] = "headings"
    widgets["topTen"]["columns"] = ("Destination")

    for columnName in widgets["topTen"]["columns"]:
        widgets["topTen"].column(columnName, width=250, anchor="e")
        widgets["topTen"].heading(columnName, text=columnName)

    widgets["topTen"].grid(row=5, column=0, columnspan=2, pady=5)


    # Common data table
    widgets["commonData"] = ttk.Treeview(root, height=10)
    widgets["commonData"]["show"] = "headings"
    widgets["commonData"]["columns"] = ("Data")

    for columnName in widgets["commonData"]["columns"]:
        widgets["commonData"].column(columnName, width=250)
        widgets["commonData"].heading(columnName, text=columnName)

    widgets["commonData"].grid(row=5, column=2, columnspan=2, pady=5)

    return (root, widgets)


# Exit function, called when the user closes the window
def exitprogram(sniffer):
    sniffer.stop()
    sniffer.graphicsHandle[0].destroy()


    

## Main program
###############################################################################


# packetHandler is set up below as the callback function for processing a packet
def packetHandler(self, data):
    widgets = self.graphicsHandle[1]

    # Decode IP addresses by version
    if data["version"] == 4:
        destination = decodeIPv4(data['destinationAddr'])
        source      = decodeIPv4(data['sourceAddr'])
        protocol    = data["protocol"]

    if data["version"] == 6:
        destination = decodeIPv6(data['destinationAddr'])
        source      = decodeIPv6(data['sourceAddr'])
        protocol    = data["nextHeader"]
        
    
    # Return if filters are enabled and something doesn't match up; this is makes filter function.
    if self.filterEnabled.get():#Checks in filter is enabled
        if widgets["protocolFilter"].get() != protocols[protocol]:#Checks if protocol is the same as the filter
            return
            
        #if widgets[*Filter].get() != packetProperty
            #return
            
            

    direction = "(Neither)"
    # Count packets in and out as well as total
    if destination == self.ip4 or destination == self.ip6:#Checks if packets are Incoming
        self.packetsIn += 1#Adds one to total outgoing packets(which is displayed)
        direction = "Incoming"#Declares the direction
    elif source == self.ip4 or source == self.ip6:#Checks if packets are outgoing
        self.packetsOut += 1#Adds one to total outgoing packets(which is displayed)
        direction = "Outgoing"#Declares the direction

    self.numPackets += 1#Adds one number of packets as a whole.
    self.payloads.append(data["decodedPayload"])#Adds payload

    # Tally how many packets have been sent to a destination address
    # Add a new entry to the dictionary with 1 visit if there isn't one,
    # otherwise increment the existing one
    if destination != self.ip4 and destination != self.ip6:
        if destination in self.topDestinations:
            self.topDestinations[destination] += 1
        else:
            self.topDestinations[destination] = 1


    # The destination tally is a dictionary, structured { domain: tally, domain: tally, ... }
    # In order to get a top ten list, they need to be zipped together, sorted,
    # and then have the destinations extracted
    orderedTop = [
        dest for hits, dest in sorted(zip(
            self.topDestinations.values(),
            self.topDestinations.keys()
        ))
    ]

    # Push matches of our regexes into the common word capture list
    for regex in self.regexes:
        matches = regex.findall(data["decodedPayload"])
        matches = filter(None, matches)  # Don't push empty matches

        for item in matches:
            if item not in self.commonData:
                self.commonData.append(item)

    # Extract TCP sequence number
    tcpSequenceNum = "(N/A)"#TCP sequence number will be set as N/A, if protocol isn't TCP because it won't have one.
    rowcolor       = "None"#If protocol isn't TCP, it will not be color-coded

    if protocol == 6:#6 signifies TCP, so if protocol is == 6...
        tcpSequenceNum = data["tcp"]["sequenceNumber"]#The TCP Sequence Number is set
        rowcolor       = addRowColor(widgets["table"], tcpSequenceNum)#Row color is set using this function.


    # Update the graphics window        
    widgets["table"].insert("", 0, values=(
        self.numPackets,              # Total number of packets so far
        data["timestamp"],            # Timestamp of current packet
        source,                       # Source address
        destination,                  # Destination address
        direction,                    # Incoming vs Outgoing
        len(data["decodedPayload"]),  # Payload length
        protocols[protocol],          # Protocol
        tcpSequenceNum                # TCP sequence number
    ), tags=(rowcolor,))

    # Clear and repopulate top ten destinations
    widgets["topTen"].delete(*widgets["topTen"].get_children())

    for destination in reversed(orderedTop[:10]):
        widgets["topTen"].insert("", 0, values=(destination))

    # Insert common data to list if it's not already there
    if len(self.commonData) > 0:
        currentItem = self.commonData[-1]

        topItem = widgets["commonData"].identify("item", 0, 26)  # Coords of first row, as if user clicked there
        topItem = widgets["commonData"].item(topItem, "values")

        # Use empty string if there's no data yet
        if len(topItem) == 0:
            topItem = ""
        else:
            topItem = topItem[0]

        if currentItem != topItem:
            widgets["commonData"].insert("", 0, values=(currentItem))


    # Update the packets count
    widgets["packetsIn"].config(text="Packets in: " + str(self.packetsIn))
    widgets["packetsOut"].config(text="Packets out: " + str(self.packetsOut))


def main():
    try:
        # Create our main sniffer
        sniffer = PacketSniffer()
        sniffer.payloads = []

        # Create the main graphics window
        sniffer.graphicsHandle = initGraphicsWindow(sniffer)

        # Set the function above as our packet handler
        sniffer.onPacket = packetHandler

        # Create new variables to modify later in our packet handler
        sniffer.packetsIn  = 0
        sniffer.packetsOut = 0
        sniffer.numPackets = 0

        sniffer.topDestinations = {}
        sniffer.commonData      = [""]

        # Regexes need to be careful, they will be parsing random binary data
        # and sometimes encounter issues using ranges
        azAZ09 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

        sniffer.regexes = [
            re.compile(r'[{0}]+@[{0}]+\.[{0}]{{2,3}}'.format(azAZ09)),  # email address
            re.compile(r'[0-9]{3}[-_.][0-9]{3}[-_.][0-9]{4}'),  # phone number
            re.compile(r'(http(?:s)?://[a-zA-Z0-9]+\.[a-zA-z]{2,3}(?:[a-zA-Z0-9+-=_%.]+)?)')  # URL
        ]

        # Run the graphics window, let it take over
        sniffer.graphicsHandle[0].mainloop()

    except pcapError as e:
        # The sniffer object may or may not exist depending on where
        # the exception was encountered
        try:
            sniffer.graphicsHandle[0].withdraw()
        except:
            root = Tk()
            root.withdraw()

        messagebox.showerror("PCAP Error", e)


if __name__ == "__main__":
    main()
