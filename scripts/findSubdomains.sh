{
	crt $1;
	subfinder -d $1 -all -silent;
	abusedb -d $1;
	chaos -d $1 -silent;
} | sort -u
