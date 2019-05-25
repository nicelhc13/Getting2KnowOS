gcc -o seq_read seq_read.c
size=$((1<<10))
end=$((1<<30))
while : ; do
    time ./seq_read $size
    size=$((size<<1))
    if [[ ${size} -gt ${end} ]]
    then
            break;
    fi
done
