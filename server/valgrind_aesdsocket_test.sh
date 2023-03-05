#!/bin/sh

valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose --log-file=/tmp/valgrid-out.txt ./aesdsocket

echo "CHECK the output log in /tmp/valgrid-out.txt"
