import time,random
def time_random():
	t=time.time()
	base=time.strftime("%Y-%m-%d-%H-%M-%S-", time.localtime(t))
	ms=f"{int((t-int(t))*1000):03d}-"
	now_time=base+ms
	random_num=random.randint(0,10000)
	return f'{now_time}{random_num:05d}'