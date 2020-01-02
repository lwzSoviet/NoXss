#########################################################################
# File Name: batchjob.sh
# Author: longwenzhang
#Created Time:2019.12.31
#########################################################################
#!/bin/bash

#Scan big data in batch to avoid highly use of cpu&memory.
python start.py --file url --filter
line=`cat url.filtered|wc -l`
if [ $line -lt 10000 ]
then
	python start.py --file url.filtered
else
	start=1
	count=10000
	end=10000
	while [ $end -lt $line ]
	do
		sed -n "$start,$end p" url.filtered>url.slice
		# delete traffic files after scanning.
		python start.py --file url.slice --clear
		let start+=count
		let end+=count
	done
	sed -n "$start,$line p" url.filtered>url.slice
	# delete traffic files after scanning.
	python start.py --file url.slice --clear
	cat urls.slice
fi
