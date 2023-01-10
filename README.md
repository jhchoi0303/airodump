# airodump
## Install dependencies
``` 
sudo apt-get install libpcap0.8-dev
sudo apt-get install libc6-dev
```

## Debugging (Kali)

### Using dummy interface
```
modprobe mac80211_hwsim
ifconfig wlan1 down
iwconfig wlan1 mode monitor
ifconfig wlan1 up
```

### Send packet through dummy interface
```
sudo bittwist -v -i wlan1 [pcapfile location]
```


## Build and execute
```
make
./airodump <interface>
```
