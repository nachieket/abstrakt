def printf(*args, logger=None):
  line = ' '.join(map(str, args))

  if logger:
    print(line)
    logger.info(line)
  else:
    print(line)
