#!/usr/bin/env bash

{
	echo $1 | gau;
	echo $1 | waybackurls;
} | sort -u

