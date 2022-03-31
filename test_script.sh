for TEST in test_hello_world test_large_array_seq test_large_array_rand
do
    for PAGER in apager dpager hpager
	do
	    for (( i=1; i<=10; i++ ))
		do
	       	     ./${PAGER} ./tests/${TEST}
		done	
	done
done
