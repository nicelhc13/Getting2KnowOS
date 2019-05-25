gcc -o seq_write_read seq_write_read.c
size=$((1<<10))
end=$((1<<26))
while : ; do
    rm /tmp/seq_write_read
    rm /tmp/seq_write_read.c
    rm /tmp/1GBWrite
    time ./seq_write_read $size 4
    size=$((size<<1))
    if [[ ${size} -gt ${end} ]]
    then
            break;
    fi
done
