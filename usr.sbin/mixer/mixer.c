/*
 *	This is an example of a mixer program for Linux
 *
 *	updated 1/1/93 to add stereo, level query, broken
 *      	devmask kludge - cmetz@thor.tjhsst.edu
 *
 * (C) Craig Metz and Hannu Savolainen 1993.
 *
 * You may do anything you wish with this program.
 *
 * ditto for my modifications (John-Mark Gurney, 1997)
 *
 * $FreeBSD: src/usr.sbin/mixer/mixer.c,v 1.11.2.6 2001/07/30 10:22:58 dd Exp $
 * $DragonFly: src/usr.sbin/mixer/mixer.c,v 1.6 2004/04/15 12:58:12 joerg Exp $
 */

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/soundcard.h>

#define LEFT(vol) (vol & 0x7f)
#define RIGHT(vol) ((vol >> 8) & 0x7f)

static const char *names[SOUND_MIXER_NRDEVICES] = SOUND_DEVICE_NAMES;
static const char *defaultdev = "/dev/mixer";

static void	usage(int devmask, int recmask);
static int	res_name(const char *name, int mask);
static void	print_recsrc(int recsrc);
static void	print_recsrc_short(int recsrc);

void
usage(int devmask, int recmask)
{
	int i, n;

	printf("usage: mixer [-f device] [-s] [dev [+|-][voll[:[+|-]volr]] ...\n"
	       "       mixer [-f device] [-s] recsrc ...\n"
	       "       mixer [-f device] [-s] {^|+|-|=}rec recdev ...\n"
	       "       mixer -h\n");
	printf(" devices: ");
	for (i = 0, n = 0; i < SOUND_MIXER_NRDEVICES; i++) {
		if ((1 << i) & devmask)  {
			if (n)
				printf(", ");
			printf("%s", names[i]);
			n = 1;
		}
	}
	printf("\n rec devices: ");
	for (i = 0, n = 0; i < SOUND_MIXER_NRDEVICES; i++) {
		if ((1 << i) & recmask)  {
			if (n)
				printf(", ");
			printf("%s", names[i]);
			n = 1;
		}
	}
	printf("\n");
	exit(1);
}

int
res_name(const char *name, int mask)
{
	int i;

	for (i = 0; i < SOUND_MIXER_NRDEVICES; i++)
		if ((1 << i) & mask && !strcmp(names[i], name))
			break;

	if (i == SOUND_MIXER_NRDEVICES)
		return(-1);

	return(i);
}

void
print_recsrc(int recsrc)
{
	int i, n = 0;
	printf("Recording source: ");

	for (i = 0; i < SOUND_MIXER_NRDEVICES; i++) {
		if ((1 << i) & recsrc) {
			if (n)
				printf(", ");
			printf("%s", names[i]);
			n = 1;
		}
	}
	printf("\n");
}

void
print_recsrc_short(int recsrc)
{
	int i, first;

	first = 1;

	for (i = 0; i < SOUND_MIXER_NRDEVICES; i++) {
		if ((1 << i) & recsrc) {
			if (first) {
				printf("=rec ");
				first = 0;
			}
			printf("%s ", names[i]);
		}
	}
}

int
main(int argc, char **argv)
{
	int i, mset, fd, dev;
	int devmask = 0, recmask = 0, recsrc = 0, orecsrc;
	int dusage = 0, drecsrc = 0, shortflag = 0;
	int l = 0, r = 0, t = 0;
	int n = 0, lrel = 0, rrel = 0;
	char lstr[8], rstr[8];
	char ch;

	const char *name = defaultdev;

	while ((ch = getopt(argc, argv, "f:sh")) != -1)
		switch (ch) {
			case 'f':
				name = optarg;
				break;
			case 's':
				shortflag = 1;
				break;
			case 'h': /* Fall through */
			default:
				dusage = 1;
		}
	argc -= optind;
	argv += optind;

	if ((fd = open(name, O_RDWR)) < 0)
		err(1, "%s", name);
	if (ioctl(fd, SOUND_MIXER_READ_DEVMASK, &devmask) == -1)
		err(1, "SOUND_MIXER_READ_DEVMASK");
	if (ioctl(fd, SOUND_MIXER_READ_RECMASK, &recmask) == -1)
		err(1, "SOUND_MIXER_READ_RECMASK");
	if (ioctl(fd, SOUND_MIXER_READ_RECSRC, &recsrc) == -1)
		err(1, "SOUND_MIXER_READ_RECSRC");
	orecsrc = recsrc;

	if (dusage) {
		close(fd);
		usage(devmask, recmask); /* Does not return */
	}

	if (argc == 0) {
		for (i = 0; i < SOUND_MIXER_NRDEVICES; i++) {
			if (!((1 << i) & devmask)) 
				continue;
			if (ioctl(fd, MIXER_READ(i),&mset)== -1) {
			   	warn("MIXER_READ");
				continue;
			}
			if (shortflag)
				printf("%s %d:%d ", names[i], LEFT(mset),
				       RIGHT(mset));
			else
				printf("Mixer %-8s is currently set to %3d:%d\n",
				       names[i], LEFT(mset), RIGHT(mset));
		}
		if (ioctl(fd, SOUND_MIXER_READ_RECSRC, &recsrc) == -1)
			err(1, "SOUND_MIXER_READ_RECSRC");
		if (shortflag) {
			print_recsrc_short(recsrc);
			if (isatty(STDOUT_FILENO))
				printf("\n");
		} else
			print_recsrc(recsrc);
		exit(0);
	}



	while (argc > 0) {
		if (!strcmp("recsrc", *argv)) {
			drecsrc = 1;
			argc--; argv++;
			continue;
		} else if (argc > 1 && !strcmp("rec", *argv + 1)) {
			if (**argv != '+' && **argv != '-' &&
			    **argv != '=' && **argv != '^') {
				warnx("unknown modifier: %c", **argv);
				dusage = 1;
				break;
			}
			if ((dev = res_name(argv[1], recmask)) == -1) {
				warnx("unknown recording device: %s", argv[1]);
				dusage = 1;
				break;
			}
			switch(**argv) {
			case '+':
				recsrc |= (1 << dev);
				break;
			case '-':
				recsrc &= ~(1 << dev);
				break;
			case '=':
				recsrc = (1 << dev);
				break;
			case '^':
				recsrc ^= (1 << dev);
				break;
			}
			drecsrc = 1;
			argc -= 2; argv += 2;
			continue;
		}

		if ((t = sscanf(*argv, "%d:%d", &l, &r)) > 0) {
			dev = 0;
		}
		else if((dev = res_name(*argv, devmask)) == -1) {
			warnx("unknown device: %s", *argv);
			dusage = 1;
			break;
		}

#define	issign(c)	(((c) == '+') || ((c) == '-'))

		if (argc > 1) {
			n = sscanf(argv[1], "%7[^:]:%7s", lstr, rstr);
			if (n > 0) {
				if (issign(lstr[0]))
					lrel = rrel = 1;
				l = atoi(lstr);
			}
			if (n > 1) {
				rrel = 0;
				if (issign(rstr[0]))
					rrel = 1;
				r = atoi(rstr);
			}
		}

		switch(argc > 1 ? n : t) {
		case 0:
			if (ioctl(fd, MIXER_READ(dev),&mset)== -1) {
				warn("MIXER_READ");
				argc--; argv++;
				continue;
			}
			if (shortflag)
				printf("%s %d:%d ", names[dev], LEFT(mset),
				       RIGHT(mset));
			else
				printf("Mixer %-8s is currently set to %3d:%d\n",
				       names[dev], LEFT(mset), RIGHT(mset));

			argc--; argv++;
			break;
		case 1:
			r = l;
		case 2:
			if (ioctl(fd, MIXER_READ(dev),&mset)== -1) {
				warn("MIXER_READ");
				argc--; argv++;
				continue;
			}

			if (lrel)
				l += LEFT(mset);
			if (rrel)
				r += RIGHT(mset);

			if (l < 0)
				l = 0;
			else if (l > 100)
				l = 100;
			if (r < 0)
				r = 0;
			else if (r > 100)
				r = 100;

			printf("Setting the mixer %s to %d:%d.\n", names[dev],
			       l, r);

			l |= r << 8;
			if (ioctl(fd, MIXER_WRITE(dev), &l) == -1)
				warn("WRITE_MIXER");

			argc -= 2; argv += 2;
 			break;
		}
	}

	if (orecsrc != recsrc)
		if (ioctl(fd, SOUND_MIXER_WRITE_RECSRC, &recsrc) == -1)
			err(1, "SOUND_MIXER_WRITE_RECSRC");
 
	if (drecsrc) {
		if (ioctl(fd, SOUND_MIXER_READ_RECSRC, &recsrc) == -1)
			err(1, "SOUND_MIXER_READ_RECSRC");
		print_recsrc(recsrc);
	}

	close(fd);

	exit(0);
}
