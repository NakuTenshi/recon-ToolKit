for d in $(cat $1);
do 
	result=$(curl -s "https://crt.sh/?q=$d&output=json" | jq -r '.[] | .name_value, .common_name' | sort -u)
	svaing_file="${d}.crt"
	echo "saving subdomains from $d to $svaing_file"
	echo "$result" > $svaing_file
	
done

