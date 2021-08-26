import pygame
import sys
from datetime import datetime


cleanedCnt = 0
timeStr = ""


def main():
    if(len(sys.argv) != 3):
        print("incorrect number of arguments given")
        print("Using \"command-and-control-servers.list\" and \"malware-payload-urls.list\" as default")

    ccServ = open(sys.argv[1], 'r')
    badIPs = ccServ.read().splitlines()
    badIPs = validIPs(badIPs)
    malHost = open(sys.argv[2], 'r')
    malIPs = malHost.read().splitlines()
    malIPs = validIPs(badIPs)

    #sort and filter
    print("\nStarting recursive IP insertion sort:")
    badIPs = ip_insertionSort(badIPs, 3)
    top10Total = getTop10D1(badIPs)
    malIPs = ip_insertionSort(malIPs, 3)

    #find most dangerous IP/8 and IP
    worst8 = [[]]
    worst8 = getSlash(badIPs, 0)
    top10Worst8 = getTop10D2(worst8)
    mal8 = [[]]
    mal8 = getSlash(malIPs, 0)
    for bad in worst8:
        if((not(isinstance(bad[0], int))) and (bad[1] != 0)):
            print(bad[0]+".0.0.0/8 hosts "+str(bad[1]))
	
    now = datetime.now()
    global timeStr
    timeStr = str(now.strftime("%Y-%B-%d_%H:%M"))
    dispSetup(top10Worst8, top10Total)
    pygameHilbert(worst8, mal8)


def dispSetup(worst8, topIPs):
    with open("template.html", 'r') as template:
        htmlSrc = template.read()
    template.close()
    fileName = timeStr+".html"
    with open(fileName, 'w') as outPage:
        rplStr = htmlSrc.replace("screenshot", timeStr)
        rplStr = rplStr.replace("rplc0rng", worst8[0][0])
        rplStr = rplStr.replace("rplc1rng", worst8[1][0])
        rplStr = rplStr.replace("rplc2rng", worst8[2][0])
        rplStr = rplStr.replace("rplc3rng", worst8[3][0])
        rplStr = rplStr.replace("rplc4rng", worst8[4][0])
        rplStr = rplStr.replace("rplc5rng", worst8[5][0])
        rplStr = rplStr.replace("rplc6rng", worst8[6][0])
        rplStr = rplStr.replace("rplc7rng", worst8[7][0])
        rplStr = rplStr.replace("rplc8rng", worst8[8][0])
        rplStr = rplStr.replace("rplc9rng", worst8[9][0])
        rplStr = rplStr.replace("rplc0ip", topIPs[0][0])
        rplStr = rplStr.replace("rplc1ip", topIPs[1][0])
        rplStr = rplStr.replace("rplc2ip", topIPs[2][0])
        rplStr = rplStr.replace("rplc3ip", topIPs[3][0])
        rplStr = rplStr.replace("rplc4ip", topIPs[4][0])
        rplStr = rplStr.replace("rplc5ip", topIPs[5][0])
        rplStr = rplStr.replace("rplc6ip", topIPs[6][0])
        rplStr = rplStr.replace("rplc7ip", topIPs[7][0])
        rplStr = rplStr.replace("rplc8ip", topIPs[8][0])
        rplStr = rplStr.replace("rplc9ip", topIPs[9][0])
        outPage.write(rplStr)
    outPage.close()
    for space in worst8:
        for ip in topIPs:
            if(space[0] == ip[0].split('.')[0]):
                print(ip[0])


def getTop10D2(badItem):
    badSpaces = []
    for item in badItem:
        if(len(item) > 0):
            itemOne = item[1]
            itemZero = item[0]
            badSpace = {"one": itemOne, "zero": itemZero}
            badSpaces.append(badSpace)
    badSpaces.sort(key=retOne)
    retSpaces = []
    spacesLen = len(badSpaces)
    for q in range(10):
        bad = badSpaces[(spacesLen - q) - 1]
        retVal = str(bad["zero"])
        retCnt = int(bad["one"])
        retItem = [retVal, retCnt]
        retSpaces.append(retItem)
    return retSpaces


def getTop10D1(badList):
    twoD = [[]]
    prevItem = ''
    thisCnt = 0
    for item in badList:
        if(item == prevItem):
            thisCnt = thisCnt + 1
        else:
            temp = [str(item), int(thisCnt + 1)]
            twoD.append(temp)
            prevItem = item
            thisCnt = 0
    twoD.pop(0)
    first = twoD[0]
    second = twoD[1]
    if(first[0] == second[0]):
        replacement = [str(second[0]), int(second[1] + 1)]
        twoD.pop(0)
        twoD[0] = replacement
    retList = getTop10D2(twoD)
    return retList


def retOne(item):
    return item["one"]


def validIPs(ipList):#dec.dec.dec.dec, 0.0.0.0, 10.0.0.0/8, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    retList = []
    for ip in ipList:
        retBool = True
        junk = ip.split(':')
        string = junk[0]
        if(string.count('.') == 3):
            parts = string.split('.')
            for num in parts:
                if(num.isdigit()):
                    num = int(num)
                    if((num >= 256) and (num < 0)):
                        retBool = False
                else:
                    retBool = False
            if(parts[0] == "127" or parts[0] == "10"):
                retBool = False
            if(parts[0] == "172" and ((int(parts[1]) >= 16) and int(parts[1]) <= 31)):
                retBool = False
            if(parts[0] == "192" and parts[1] == "168"):
                retBool = False
            if(parts[0] == "0" and parts[1] == "0" and parts[2] == "0" and parts[3] == "0"):
                retBool = False
        else:
            retBool =False
        if(retBool):
            retList.append(string)
    return retList



def ip_insertionSort(inputList, t):
    for e in range(1, len(inputList)):
        r = e - 1
        nxtElement = inputList[e]
        while(int(inputList[r].split('.')[t]) > int(nxtElement.split('.')[t])) and (r >= 0):
            inputList[r+1] = inputList[r]
            r = r - 1
        inputList[r+1] = nxtElement
    if(t == 0):
        return inputList
    else:
        return ip_insertionSort(inputList, t-1)


def getSlash(ipList, deg):
    worstDeg = [[]]
    allDegs = []
    for ip in ipList:
        splits = ip.split('.')
        allDegs.append(splits[deg])
    row = len(ipList)
    col = 2
    worstDeg = [[0 for col in range(col)] for row in range(row)]
    y = 0
    for slash in [ele for ind, ele in enumerate(allDegs,1) if ele not in allDegs[ind:]]:
        worstDeg[y] = [slash, allDegs.count(slash)]
        y = y + 1
    return worstDeg


def pygameHilbert(worst, mal):
    pygame.init()
    screen = pygame.display.set_mode((60*16, 60*16))
    rows = [[0, 1, 14, 15, 16, 19, 20, 21, 234, 235, 236, 239, 240, 241, 254, 255], [3, 2, 13, 12, 17, 18, 23, 22, 233, 232, 237, 238, 243, 242, 253, 252], [4, 7, 8, 11, 30, 29, 24, 25, 230, 231, 226, 225, 244, 247, 248, 251], [5, 6, 9, 10, 31, 28, 27, 26, 229, 228, 227, 224, 245, 246, 249, 250], [58, 57, 54, 53, 32, 35, 36, 37, 218, 219, 220, 223, 202, 201, 198, 197], [59, 56, 55, 52, 33, 34, 39, 38, 217, 216, 221, 222, 203, 200, 199, 196], [60, 61, 50, 51, 46, 45, 40, 41, 214, 215, 210, 209, 204, 205, 194, 195], [63, 62, 49, 48, 47, 44, 43, 42, 213, 212, 211, 208, 207, 206, 193, 192], [64, 67, 68, 69, 122, 123, 124, 127, 128, 131, 132, 133, 186, 187, 188, 191], [65, 66, 71, 70, 121, 120, 125, 126, 129, 130, 135, 134, 185, 184, 189, 190], [78, 77, 72, 73, 118, 119, 114, 113, 142, 141, 136, 137, 182, 183, 178, 177], [79, 76, 75, 74, 117, 116, 115, 112, 143, 140, 139, 138, 181, 180, 179, 176], [80, 81, 94, 95, 96, 97, 110, 111, 144, 145, 158, 159, 160, 161, 174, 175], [83, 82, 93, 92, 99, 98, 109, 108, 147, 146, 157, 156, 163, 162, 173, 172], [84, 87, 88, 91, 100, 103, 104, 107, 148, 151, 152, 155, 164, 167, 168, 171], [85, 86, 89, 90, 101, 102, 105, 106, 149, 150, 153, 154, 165, 166, 169, 170]]#This is not efficient programming, I am well aware. I tried the prettier algorithms but I gave up after trying and failing too much
    DARKGRAY = (36, 36, 36)
    WHITE = (255, 255, 255)
    screen.fill(WHITE)
    fill16x16(60, worst, mal, screen, rows)
    draw16x16(60, 2, DARKGRAY, screen)#overlay the nice gray
    mapName = timeStr + ".jpg"
    pygame.image.save(screen, mapName)


def draw16x16(boxSize, space, color, screen):
    for x in range(16):
        for y in range(16):
            myRect = pygame.Rect(x*boxSize, y*boxSize, boxSize, boxSize)
            pygame.draw.rect(screen, color, myRect, space)


def fill16x16(boxSize, worst, mal, screen, rows):
    c2Weight = 4
    malWeight = 2
    worst = populate(worst)
    mal = populate(mal)
    masterCnt = 0
    usedCnt = 0
    myfont = pygame.font.SysFont("Liberation Sans Narrow", 30)
    for y in range(16):
        row = rows[y]
        for x in range(16):
            thisRed = 255
            thisGreen = 255
            thisBlue = 255
            wantedVal = row[x]
            badVal = grabBad(wantedVal, worst)
            malVal = grabBad(wantedVal, mal)
            if((len(badVal) == 2) or (len(malVal) == 2)):
                redness = 0
                yellowness = 0
                if(len(badVal) == 2):
                    redness = badVal[1] * c2Weight
                thisBlue = thisBlue - redness
                thisGreen = thisGreen - redness
                if(len(malVal) == 2):
                    yellowness = malVal[1]
                    yellowness = yellowness * malWeight
                thisBlue = thisBlue - yellowness
                if(thisGreen < 0):
                    thisGreen = 0
                if(thisBlue < 0):
                    thisBlue = 0
            color = (thisRed, thisGreen, thisBlue)
            myRect = pygame.Rect(x*boxSize, y*boxSize, boxSize, boxSize)
            pygame.draw.rect(screen, color, myRect, 0)
            label = myfont.render(str(wantedVal), 1, (0, 0, 0))
            screen.blit(label, ((x*boxSize)+6, y*boxSize))
            masterCnt = masterCnt + 1


def populate(incomplete):
    retList = []
    cnter = 0
    for n in range(256):
        item = incomplete[cnter]
        if(len(item) == 2):
            comp = int(item[0])
            ipCnt = int(item[1])
            if(n == comp):
                retList.append([n, ipCnt])
                cnter = cnter + 1
            else:
                retList.append([n, 0])
        else:
            retList.append([n, 0])
    return retList


def grabBad(wantedVal, array):
    for i in array:
        if(i[0] == wantedVal):
            return i
    print("That's an error in grabBad(), bub")



main()
