default: clean apager dpager hpager test_input
	#gcc -static hloader.c -o hloader 
apager:
	gcc -g -fPIE -fPIC -Bstatic -static -static-libgcc -Wl,-Ttext-segment=0x20000000 apager.c -o apager

dpager:
	gcc -g -Bstatic -fPIE -fPIC -Bstatic -static -static-libgcc -Wl,-Ttext-segment=0x20000000 dpager.c -o dpager

hpager:
	gcc -g -Bstatic -fPIE -fPIC -Bstatic -static -static-libgcc -Wl,-Ttext-segment=0x20000000 hpager.c -o hpager
	gcc -g -Bstatic -fPIE -fPIC -Bstatic -static -static-libgcc -Wl,-Ttext-segment=0x20000000 hpager_not_predict.c -o hpager_n

test_input:
	gcc -O0 -g -Bstatic -fPIE -fPIC -Bstatic -static -static-libgcc -Wl,-Ttext-segment=0x4000000 test1.c -o test1
	gcc -O0 -g -Bstatic -fPIE -fPIC -Bstatic -static -static-libgcc -Wl,-Ttext-segment=0x4000000 test2.c -o test2
	gcc -O0 -g -Bstatic -fPIE -fPIC -Bstatic -static -static-libgcc -Wl,-Ttext-segment=0x4000000 test3.c -o test3
	gcc -O0 -g -Bstatic -fPIE -fPIC -Bstatic -static -static-libgcc -Wl,-Ttext-segment=0x4000000 test4.c -o test4
	gcc -O0 -g -Bstatic -fPIE -fPIC -Bstatic -static -static-libgcc -Wl,-Ttext-segment=0x4000000 zero.c -o zero

clean:
	rm -rf apager hpager dpager test1 test2 test3 test4 zero
	
