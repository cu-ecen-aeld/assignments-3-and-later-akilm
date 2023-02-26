if [ -z $1 ] || [ -z $2 ]
then
    echo "Two arguments expected"
    exit 1
fi

filesdir=$1
searchstr=$2

#check filesdir represents a directory on the filesystem
if ! [ -d $filesdir ]
then
    echo "Directory does not exist"
    exit 1
fi

file_count=0
match_count=0
for file in $(find $filesdir -type f -print)
do
    echo $file
    file_count=$(($file_count+1))
    match_count=$(($match_count+$(grep -c $searchstr $file)))
done

echo "The number of files are $file_count and the number of matching lines are $match_count"

