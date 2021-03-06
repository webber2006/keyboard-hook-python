"""
windows7 64bit, python3.x 32bit
32bit 키값 변환기
후킹 후 나온 키값을 실질적인 값으로 변경해줌
python3.x 64비트 사용시 다른 키값이 나올 수 있음
키보드 마다 다른 키값을 출력할 수 있음(수정해서 사용)
"""

# 후킹값 : 실질적 키값
ID_TO_KEY = {
    27: 'Esc',
	112: 'F1',
	113: 'F2',
	114: 'F3',
	115: 'F4',
	116: 'F5',
	117: 'F6',
	118: 'F7',
	119: 'F8',
	120: 'F9',
	121: 'F10',
	122: 'F11',
	123: 'F12',
	44: 'Prt Sc',
	145: 'Scroll Lock',
	19: 'Pause Break',
	192: '`',
	49: '1',
	50: '2',
	51: '3',
	52: '4',
	53: '5',
	54: '6',
	55: '7',
	56: '8',
	57: '9',
	48: '0',
	189: '-',
	187: '=',
	220: '|',
	8: 'Back Space',
	45: 'Insert',
	36: 'Home',
	33: 'Page Up',
	46: 'Delete',
	35: 'End',
	34: 'PageDown',
	9: 'Tab',
	65: 'a',
	66: 'b',
	67: 'c',
	68: 'd',
	69: 'e',
	70: 'f',
	71: 'g',
	72: 'h',
	73: 'i',
	74: 'j',
	75: 'k',
	76: 'l',
	77: 'm',
	78: 'n',
	79: 'o',
	80: 'p',
	81: 'q',
	82: 'r',
	83: 's',
	84: 't',
	85: 'u',
	86: 'v',
	87: 'w',
	88: 'x',
	89: 'y',
	90: 'z',
	20: 'Caps Lock',
	160: 'Shift(L)',
	162: 'Ctrl(L)',
	91: 'Window Key(L)',
	32: 'Space',
	21: 'K/E Or ALt(R)',
	92: 'Window Key(R)',
	93: 'Fn',
	25: 'Ctrl(R)/한자',
	161: 'Shift(R)',
	13: 'Enter',
	219: '[',
	221: ']',
	186: ';',
	222: '\'',
	188: ',',
	190: '.',
	191: '/',
	38: 'Uk',
	40: 'Dk',
	37: 'Lk',
	39: 'Rk',
	144: 'NumLock(tenKey)',
	111: '/(tenKey)',
	106: '*(tenKey)',
	109: '-(tenKey)',
	97: '1(tenKey)',
	98: '2(tenKey)',
	99: '3(tenKey)',
	100: '4(tenKey)',
	101: '5(tenKey)',
	102: '6(tenKey)',
	103: '7(tenKey)',
	104: '8(tenKey)',
	105: '9(tenKey)',
	96: '0(tenKey)',
	107: '+(tenKey)',
	13: 'Enter(tenKey)',
	110: '.(tenKey)',
        18: 'Alt(L)'
        }

# 해석할 파일([FILE_A]를 변경하여 사용)
f1 = open('[FILE_A]')
# 해석된 후 저장할 값([FILE_B]를 변경하여 사용)
f2 = open('[FILE_B]', 'a')

# 키값 해석
for line in f1:
    f2.writelines(str(ID_TO_KEY.get(int(line))) + '\n')

f1.close()
f2.close()
