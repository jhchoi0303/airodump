#Makefile
all:	airodump

airodump:	main.o
	g++ -o airodump	 main.o -lpcap

main.o:	ieee80211.h	radiotap.h	main.cpp

clean:
	rm -f airodump
	rm -f *.o
