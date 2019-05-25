gcc -o seq_write seq_write.c
size=$((1<<23))
end=$((1<<26))
while : ; do
    rm /tmp/seq_write
    rm /tmp/seq_write.c
    rm /tmp/1GBWrite
    time ./seq_write $size
    size=$((size<<1))
    if [[ ${size} -gt ${end} ]]
    then
            break;
    fi
done
