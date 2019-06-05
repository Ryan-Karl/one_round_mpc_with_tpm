
parties_input = 2
levels_input = 10
val = 0
num = 0

while val < levels_input:
    circuit_range = dict(val, list(range( 2 ** (val), (2 ** (val + 1) - 1))))
    val += 1

placeholder = 1
increment = round((2**(levels_input))/parties_input)

while r < parties_input
    for k in circuit_range[levels_input]:
        if (k > ((2**(levels_input - 1) - 1) + ((placeholder - 1)  * increment))) and (k < ((2**(levels_input - 1) - 1) + (placeholder * increment))):
            print("IN " + str(circuit_range) + str(placeholder))

    r+=1

q = levels_input
while q > 0:
    s = 0
    for i in circuit_range[q]:
        print("8 " + str(i) + " " + str(circuit_range[j-1][s]) + " " + str(level_0[j-1][s+1]))
        s+=1
        s+=1
    q-=1

print("OUT 0 0")
