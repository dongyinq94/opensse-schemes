#!/bin/bash 

db_file="client.db"

kw_list=""



for ((i=0;i<32;i+=1));
do
#for ((j=31;j>=i;j--));
#d	       
		kw_list=$kw_list" "$i"to"$i
		#done
			
		
done


./spirt_client -b $db_file $kw_list

