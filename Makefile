bacurl: main.cpp base64.h hmac.h sha1.h sha256.h
	g++ -g main.cpp -o bacurl
clean:
	rm -f *.o
	rm -f bacurl
install:
	cp bacurl /usr/local/bin/bacurl
	
