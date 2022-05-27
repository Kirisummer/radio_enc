def partition(data, *points):
    ''' Split sequence into len(points) + 1 parts in specified points '''
    parts = []
    cur = 0
    for point in points:
        cur_next = cur + point
        parts.append(data[cur: cur_next])
        cur = cur_next
    parts.append(data[cur:])
    return parts

