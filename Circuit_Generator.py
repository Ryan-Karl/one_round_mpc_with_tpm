
level_9 = [0]
level_8 = list(range(1, 3))
level_7 = list(range(3, 7))
level_6 = list(range(7, 15))
level_5 = list(range(15, 31))
level_4 = list(range(31, 63))
level_3 = list(range(63, 127))
level_2 = list(range(127, 255))
level_1 = list(range(255, 511))
level_0 = list(range(511, 1023))

for i in level_0:
    if i < 767:
        print("IN " + str(i) + " 0")
    else:
        print("IN " + str(i) + " 1")

j = 0
for i in level_1:
    print("8 " + str(i) + " " + str(level_0[j]) + " " + str(level_0[j+1]))
    j+=1
    j+=1

j = 0
for i in level_2:
    print("8 " + str(i) + " " + str(level_1[j]) + " " + str(level_1[j+1]))
    j+=1
    j+=1

j = 0
for i in level_3:
    print("8 " + str(i) + " " + str(level_2[j]) + " " + str(level_2[j+1]))
    j+=1
    j+=1

j = 0
for i in level_4:
    print("8 " + str(i) + " " + str(level_3[j]) + " " + str(level_3[j+1]))
    j+=1
    j+=1

j = 0
for i in level_5:
    print("8 " + str(i) + " " + str(level_4[j]) + " " + str(level_4[j+1]))
    j+=1
    j+=1

j = 0
for i in level_6:
    print("8 " + str(i) + " " + str(level_5[j]) + " " + str(level_5[j+1]))
    j+=1
    j+=1

j = 0
for i in level_7:
    print("8 " + str(i) + " " + str(level_6[j]) + " " + str(level_6[j+1]))
    j+=1
    j+=1

j = 0
for i in level_8:
    print("8 " + str(i) + " " + str(level_7[j]) + " " + str(level_7[j+1]))
    j+=1
    j+=1

j = 0
for i in level_9:
    print("8 " + str(i) + " " + str(level_8[j]) + " " + str(level_8[j+1]))
    j+=1
    j+=1

j = 0
for i in level_9:
    print("OUT " + str(i) + " 0")
