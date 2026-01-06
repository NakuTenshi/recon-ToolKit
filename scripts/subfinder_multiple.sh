for d in $(cat $1);
do 
	result=$(subfinder -d $d -all -silent)
	svaing_file="${d}.subfinder"
	echo "saving subdomains from $d to $svaing_file"
	echo "$result" > $svaing_file
	
done

