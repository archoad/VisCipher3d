/*visCipher3d
Copyright (C) 2013 Michel Dubois

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.*/


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <png.h>
#include <openssl/bn.h>

#include <GL/gl.h>
#include <GL/glu.h>
#include <GL/glut.h>

#define WINDOW_TITLE_PREFIX "visCipher3d"
#define couleur(param) printf("\033[%sm",param)

static short winSizeW = 920,
	winSizeH = 690,
	frame = 0,
	currentTime = 0,
	timebase = 0,
	fullScreen = 0,
	displayHilbert = 0,
	rotate = 0,
	dt = 5; // in milliseconds

static int textList = 0,
	objectList = 0,
	hilbertList = 0,
	cpt = 0,
	background = 0,
	mono = 0;

static float fps = 0.0,
	rotx = -80.0,
	roty = 0.0,
	rotz = 20.0,
	xx = 0.0,
	yy = 5.0,
	zoom = 100.0,
	prevx = 0.0,
	prevy = 0.0,
	sphereRadius = 0.6,
	squareWidth = 0.055;

static BIGNUM *bn_sum, *bn_average, *bn_max, *bn_min;

static BIGNUM *randList[5000000];

typedef struct _point {
	GLdouble x, y, z;
	GLfloat r, g, b;
} point;

static point *pointsList = NULL;
static point *hilbertPointList = NULL;

static unsigned long sampleSize = 0,
	hilbertSize = 0,
	randListSize = 0,
	seuil = 60000;

double maxAll = 0.0;


void usage(void) {
	couleur("31");
	printf("Michel Dubois -- visCipher3d -- (c) 2013\n\n");
	couleur("0");
	printf("Syntaxe: visCipher3d <filename> <background color> <color type>\n");
	printf("\t<filename> -> file where the results of the AES datas be stored\n");
	printf("\t<background color> -> 'white' or 'black'\n");
	printf("\t<color type> -> 'mono' or 'multi'\n");
}


void takeScreenshot(char *filename) {
	FILE *fp = fopen(filename, "wb");
	int width = glutGet(GLUT_WINDOW_WIDTH);
	int height = glutGet(GLUT_WINDOW_HEIGHT);
	png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	png_infop info = png_create_info_struct(png);
	unsigned char *buffer = calloc((width * height * 3), sizeof(unsigned char));
	int i;

	glReadPixels(0, 0, width, height, GL_RGB, GL_UNSIGNED_BYTE, (GLvoid *)buffer);
	png_init_io(png, fp);
	png_set_IHDR(png, info, width, height, 8, PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
	png_write_info(png, info);
	for (i=0; i<height; i++) {
		png_write_row(png, &(buffer[3*width*((height-1) - i)]));
	}
	png_write_end(png, NULL);
	png_destroy_write_struct(&png, &info);
	free(buffer);
	fclose(fp);
	printf("INFO: Save screenshot on %s (%d x %d)\n", filename, width, height);
}


void drawPoint(point p) {
	glPointSize(1.0);
	glColor3f(p.r, p.g, p.b);
	glBegin(GL_POINTS);
	glNormal3f(p.x, p.y, p.z);
	glVertex3f(p.x, p.y, p.z);
	glEnd();
}


void drawSphere(point p) {
	glColor3f(p.r, p.g, p.b);
	glTranslatef(p.x, p.y, p.z);
	glutSolidSphere(sphereRadius, 8, 8);
}


void drawSquare(point p) {
	glColor3f(p.r, p.g, p.b);
	glTranslatef(p.x, p.y, p.z);
	glBegin(GL_QUADS);
	glVertex3f(-squareWidth, -squareWidth, 0.0); // Bottom left corner
	glVertex3f(-squareWidth, squareWidth, 0.0); // Top left corner
	glVertex3f(squareWidth, squareWidth, 0.0); // Top right corner
	glVertex3f(squareWidth, -squareWidth, 0.0); // Bottom right corner
	glEnd();
}


void drawLine(point p1, point p2){
	glLineWidth(1.0);
	glBegin(GL_LINES);
	glColor3f(p1.r, p1.g, p1.b);
	glNormal3f(p1.x, p1.y, p1.z);
	glVertex3f(p1.x, p1.y, p1.z);
	glVertex3f(p2.x, p2.y, p2.z);
	glEnd();
}


void drawString(float x, float y, float z, char *text) {
	unsigned i = 0;
	glPushMatrix();
	glLineWidth(1.0);
	if (background){ // White background
		glColor3f(0.0, 0.0, 0.0);
	} else { // Black background
		glColor3f(1.0, 1.0, 1.0);
	}
	glTranslatef(x, y, z);
	glScalef(0.01, 0.01, 0.01);
	for(i=0; i < strlen(text); i++) {
		glutStrokeCharacter(GLUT_STROKE_MONO_ROMAN, (int)text[i]);
	}
	glPopMatrix();
}


void drawText(void) {
	char text1[90], text2[90], text3[90], text4[90];
	sprintf(text1, "dt: %1.3f, FPS: %4.2f, Nbr elts: %ld", (dt/1000.0), fps, sampleSize);
	sprintf(text2, "Min: %s", BN_bn2dec(bn_min));
	sprintf(text3, "Max: %s", BN_bn2dec(bn_max));
	sprintf(text4, "Average: %s", BN_bn2dec(bn_average));
	textList = glGenLists(1);
	glNewList(textList, GL_COMPILE);
	drawString(-40.0, -34.0, -100.0, text1);
	drawString(-40.0, -36.0, -100.0, text2);
	drawString(-40.0, -38.0, -100.0, text3);
	drawString(-40.0, -40.0, -100.0, text4);
	glEndList();
}


void drawAxes(void) {
	float rayon = 0.1;
	float length = 100/4.0;

	// cube
	glPushMatrix();
	glLineWidth(1.0);
	glColor3f(0.8, 0.8, 0.8);
	glTranslatef(0.0, 0.0, 0.0);
	glutWireCube(100.0/2.0);
	glPopMatrix();

	// origin
	glPushMatrix();
	glColor3f(1.0, 1.0, 1.0);
	glutSolidSphere(rayon*4, 16, 16);
	glPopMatrix();

	// x axis
	glPushMatrix();
	glColor3f(1.0, 0.0, 0.0);
	glTranslatef(length/2.0, 0.0, 0.0);
	glScalef(length*5.0, 1.0, 1.0);
	glutSolidCube(rayon*2.0);
	glPopMatrix();
	glPushMatrix();
	glTranslatef(length, 0.0, 0.0);
	glRotated(90, 0, 1, 0);
	glutSolidCone(rayon*2, rayon*4, 8, 8);
	glPopMatrix();
	drawString(length+2.0, 0.0, 0.0, "X");

	// y axis
	glPushMatrix();
	glColor3f(0.0, 1.0, 0.0);
	glTranslatef(0.0, length/2.0, 0.0);
	glScalef(1.0, length*5.0, 1.0);
	glutSolidCube(rayon*2.0);
	glPopMatrix();
	glPushMatrix();
	glTranslatef(0.0, length, 0.0);
	glRotated(90, -1, 0, 0);
	glutSolidCone(rayon*2, rayon*4, 8, 8);
	glPopMatrix();
	drawString(0.0, length+2.0, 0.0, "Y");

	// z axis
	glPushMatrix();
	glColor3f(0.0, 0.0, 1.0);
	glTranslatef(0.0, 0.0, length/2.0);
	glScalef(1.0, 1.0, length*5.0);
	glutSolidCube(rayon*2.0);
	glPopMatrix();
	glPushMatrix();
	glTranslatef(0.0, 0.0, length);
	glRotated(90, 0, 0, 1);
	glutSolidCone(rayon*2, rayon*4, 8, 8);
	glPopMatrix();
	drawString(0.0, 0.0, length+2.0, "Z");
}


void drawObject(void) {
	unsigned long i;
	if (sampleSize <= seuil) {
		objectList = glGenLists(1);
		glNewList(objectList, GL_COMPILE_AND_EXECUTE);
		for (i=0; i<sampleSize; i++) {
			glPushMatrix();
			//drawLine(pointsList[i-1], pointsList[i]);
			drawSphere(pointsList[i]);
			glPopMatrix();
		}
		glEndList();
	}
}


void drawHilbert(void) {
	unsigned long i;
	hilbertList = glGenLists(1);
	glNewList(hilbertList, GL_COMPILE_AND_EXECUTE);
	for (i=0; i<hilbertSize; i++) {
		glPushMatrix();
		drawSquare(hilbertPointList[i]);
		//drawLine(hilbertPointList[i], hilbertPointList[i+1]);
		//drawSphere(hilbertPointList[i]);
		//drawPoint(hilbertPointList[i]);
		glPopMatrix();
	}
	glEndList();
}


void onReshape(int width, int height) {
	glViewport(0, 0, width, height);
	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	gluPerspective(45.0, width/height, 1.0, 1000.0);
	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();
}


void onSpecial(int key, int x, int y) {
	switch (key) {
		case GLUT_KEY_UP:
			rotx += 5.0;
			printf("INFO: x = %f\n", rotx);
			break;
		case GLUT_KEY_DOWN:
			rotx -= 5.0;
			printf("INFO: x = %f\n", rotx);
			break;
		case GLUT_KEY_LEFT:
			rotz += 5.0;
			printf("INFO: z = %f\n", rotz);
			break;
		case GLUT_KEY_RIGHT:
			rotz -= 5.0;
			printf("INFO: z = %f\n", rotz);
			break;
		default:
			printf("x %d, y %d\n", x, y);
			break;
	}
	glutPostRedisplay();
}


void onMotion(int x, int y) {
	if (prevx) {
		xx += ((x - prevx)/10.0);
		printf("INFO: x = %f\n", xx);
	}
	if (prevy) {
		yy -= ((y - prevy)/10.0);
		printf("INFO: y = %f\n", yy);
	}
	prevx = x;
	prevy = y;
	glutPostRedisplay();
}


void onIdle(void) {
	frame += 1;
	currentTime = glutGet(GLUT_ELAPSED_TIME);
	if (currentTime - timebase >= 1000.0){
		fps = frame*1000.0 / (currentTime-timebase);
		timebase = currentTime;
		frame = 0;
	}
	glutPostRedisplay();
}


void onMouse(int button, int state, int x, int y) {
	switch (button) {
		case GLUT_LEFT_BUTTON:
			if (state == GLUT_DOWN) {
				printf("INFO: left button, x %d, y %d\n", x, y);
			}
			break;
		case GLUT_RIGHT_BUTTON:
			if (state == GLUT_DOWN) {
				printf("INFO: right button, x %d, y %d\n", x, y);
			}
			break;
	}
}


void onKeyboard(unsigned char key, int x, int y) {
	char *name = malloc(20 * sizeof(char));
	switch (key) {
		case 27: // Escape
			printf("INFO: exit\n");
			printf("x %d, y %d\n", x, y);
			exit(0);
			break;
		case 'x':
			xx += 1.0;
			printf("INFO: x = %f\n", xx);
			break;
		case 'X':
			xx -= 1.0;
			printf("INFO: x = %f\n", xx);
			break;
		case 'y':
			yy += 1.0;
			printf("INFO: y = %f\n", yy);
			break;
		case 'Y':
			yy -= 1.0;
			printf("INFO: y = %f\n", yy);
			break;
		case 'f':
			fullScreen = !fullScreen;
			if (fullScreen) {
				glutFullScreen();
			} else {
				glutReshapeWindow(winSizeW, winSizeH);
				glutPositionWindow(100,100);
				printf("INFO: fullscreen %d\n", fullScreen);
			}
			break;
		case 'h':
			displayHilbert = !displayHilbert;
			printf("INFO: display Hilbert graph %d\n", displayHilbert);
			break;
		case 'r':
			rotate = !rotate;
			printf("INFO: rotate %d\n", rotate);
			break;
		case 'z':
			zoom -= 5.0;
			if (zoom < 5.0) {
				zoom = 5.0;
			}
			printf("INFO: zoom = %f\n", zoom);
			break;
		case 'Z':
			zoom += 5.0;
			printf("INFO: zoom = %f\n", zoom);
			break;
		case 'p':
			printf("INFO: take a screenshot\n");
			sprintf(name, "capture_%.3d.png", cpt);
			takeScreenshot(name);
			cpt += 1;
			break;
		default:
			break;
	}
	free(name);
	glutPostRedisplay();
}


void onTimer(int event) {
	switch (event) {
		case 0:
			break;
		default:
			break;
	}
	if (rotate) {
		rotz -= 0.2;
	} else {
		rotz += 0.0;
	}
	if (rotz > 360) rotz = 360;
	glutPostRedisplay();
	glutTimerFunc(dt, onTimer, 1);
}


void display(void) {
	glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();

	drawText();
	glCallList(textList);
//	if (displayHilbert) {
//		drawHilbert();
//		glCallList(hilbertList);
//	}

	glPushMatrix();
	glTranslatef(xx, yy, -zoom);
	glRotatef(rotx, 1.0, 0.0, 0.0);
	glRotatef(roty, 0.0, 1.0, 0.0);
	glRotatef(rotz, 0.0, 0.0, 1.0);
	drawAxes();
	if (displayHilbert) {
		glEnableClientState(GL_VERTEX_ARRAY);
		glEnableClientState(GL_COLOR_ARRAY);
		glVertexPointer(3, GL_DOUBLE, sizeof(point), hilbertPointList);
		glColorPointer(3, GL_FLOAT, sizeof(point), &hilbertPointList[0].r);
		glDrawArrays(GL_POINTS, 0, hilbertSize);
		glDrawArrays(GL_LINE_STRIP, 0, hilbertSize);
		glDisableClientState(GL_COLOR_ARRAY);
		glDisableClientState(GL_VERTEX_ARRAY);
	}
	if (sampleSize >= seuil) {
		glEnableClientState(GL_VERTEX_ARRAY);
		glEnableClientState(GL_COLOR_ARRAY);
		glVertexPointer(3, GL_DOUBLE, sizeof(point), pointsList);
		glColorPointer(3, GL_FLOAT, sizeof(point), &pointsList[0].r);
		glDrawArrays(GL_POINTS, 0, sampleSize);
		glDisableClientState(GL_COLOR_ARRAY);
		glDisableClientState(GL_VERTEX_ARRAY);
	} else {
		glCallList(objectList);
	}
	glPopMatrix();

	glutSwapBuffers();
	glutPostRedisplay();
}


void init(void) {
	if (background){ // White background
		glClearColor(1.0, 1.0, 1.0, 1.0);
	} else { // Black background
		glClearColor(0.1, 0.1, 0.1, 1.0);
	}

	GLfloat position[] = {0.0, 0.0, 0.0, 1.0};
	glLightfv(GL_LIGHT0, GL_POSITION, position);

	GLfloat modelAmbient[] = {0.5, 0.5, 0.5, 1.0};
	glLightModelfv(GL_LIGHT_MODEL_AMBIENT, modelAmbient);

	glEnable(GL_LIGHTING);
	glEnable(GL_LIGHT0);
	glEnable(GL_COLOR_MATERIAL);
	glColorMaterial(GL_FRONT, GL_AMBIENT_AND_DIFFUSE);

	glShadeModel(GL_SMOOTH);
	glEnable(GL_DEPTH_TEST);

	GLfloat no_mat[] = {0.0, 0.0, 0.0, 1.0};
	GLfloat mat_diffuse[] = {0.1, 0.5, 0.8, 1.0};
	GLfloat mat_specular[] = {1.0, 1.0, 1.0, 1.0};
	GLfloat shininess[] = {128.0};
	glMaterialfv(GL_FRONT, GL_AMBIENT, no_mat);
	glMaterialfv(GL_FRONT, GL_DIFFUSE, mat_diffuse);
	glMaterialfv(GL_FRONT, GL_SPECULAR, mat_specular);
	glMaterialfv(GL_FRONT, GL_SHININESS, shininess);
	glMaterialfv(GL_FRONT, GL_EMISSION, no_mat);

	glEnable(GL_NORMALIZE);
	glEnable(GL_AUTO_NORMAL);
	glDepthFunc(GL_LESS);

	drawObject();
}


void glmain(int argc, char *argv[]) {
	glutInit(&argc, argv);
	glutInitWindowSize(winSizeW, winSizeH);
	glutInitWindowPosition(120, 10);
	glutInitDisplayMode(GLUT_RGBA | GLUT_DOUBLE | GLUT_DEPTH);
	glutCreateWindow(WINDOW_TITLE_PREFIX);
	init();
	glutDisplayFunc(display);
	glutReshapeFunc(onReshape);
	glutSpecialFunc(onSpecial);
	glutMotionFunc(onMotion);
	glutIdleFunc(onIdle);
	glutMouseFunc(onMouse);
	glutKeyboardFunc(onKeyboard);
	glutTimerFunc(dt, onTimer, 0);
	fprintf(stdout, "INFO: OpenGL Version: %s\n", glGetString(GL_VERSION));
	glutMainLoop();
	glDeleteLists(textList, 1);
	glDeleteLists(objectList, 1);
}


void hsv2rgb(double h, double s, double v, GLfloat *r, GLfloat *g, GLfloat *b) {
	double hp = h * 6;
	if ( hp == 6 ) hp = 0;
	int i = floor(hp);
	double v1 = v * (1 - s),
		v2 = v * (1 - s * (hp - i)),
		v3 = v * (1 - s * (1 - (hp - i)));
	if (i == 0) { *r=v; *g=v3; *b=v1; }
	else if (i == 1) { *r=v2; *g=v; *b=v1; }
	else if (i == 2) { *r=v1; *g=v; *b=v3; }
	else if (i == 3) { *r=v1; *g=v2; *b=v; }
	else if (i == 4) { *r=v3; *g=v1; *b=v; }
	else { *r=v; *g=v1; *b=v2; }
}


double toDouble(BIGNUM *bn_val) {
	BIGNUM *bn_rem = BN_new();
	BIGNUM *bn_modulo = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	unsigned long long int m = 1;
	double result = 0.0;
	int i;
	char *strVal = NULL;
	BN_set_word(bn_modulo, pow(2, 52));
	BN_mod(bn_rem, bn_val, bn_modulo, ctx);
	strVal = BN_bn2dec(bn_rem);
	for (i=strlen(strVal)-1; i>=0; i--) {
		if (strVal[i]!='-') {
			result += ((strVal[i]-48) * m);
			m *= 10;
		} else {
			result *= -1;
		}
	}
	BN_clear_free(bn_rem);
	BN_clear_free(bn_modulo);
	BN_CTX_free(ctx);
	return(result);
}


void hilbert(double x, double y, double z, float xi, float xj, float yi, float yj, int n) {
	// src: http://www.fundza.com/algorithmic/space_filling/hilbert/basics/index.html
	// x and y are the coordinates of the bottom left corner
	// (xi, yi) & (xj, yj) are the i & j components of the unit x & y vectors of the frame

	static unsigned long i = 0;
	if (n <= 0) {
		hilbertPointList[i].x = x + (xi + yi)/2;
		hilbertPointList[i].y = z;
		hilbertPointList[i].z = y + (xj + yj)/2;
		i += 1;
	} else {
		hilbert(x,				y,				z, yi/2,	yj/2,	xi/2,	xj/2,	n-1);
		hilbert(x+xi/2,			y+xj/2,			z, xi/2,	xj/2,	yi/2,	yj/2,	n-1);
		hilbert(x+xi/2+yi/2,	y+xj/2+yj/2,	z, xi/2,	xj/2,	yi/2,	yj/2,	n-1);
		hilbert(x+xi/2+yi,		y+xj/2+yj,		z, -yi/2,	-yj/2,	-xi/2,	-xj/2,	n-1);
	}
}


int determineHilbertOrder(void) {
	int order = 0, n = 0;
	do {
		if ((sampleSize <= pow(4,n+1)) & (sampleSize > pow(4,n))) {
			order = n+1;
			break;
		} else {
			n += 1;
		}
	} while(n <= 8);
	return(order);
}


void populatePoints(BIGNUM *tab[]) {
	unsigned long i;
	BIGNUM *bn_x = BN_new();
	BIGNUM *bn_y = BN_new();
	BIGNUM *bn_z = BN_new();
	BIGNUM *bn_rem = BN_new();
	BIGNUM *bn_size = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	bn_sum  = BN_new();
	bn_average = BN_new();
	bn_max = BN_new();
	bn_min = BN_new();
	double hue = 0.0;
	pointsList = (point*)calloc(sampleSize, sizeof(point));
	srand(time(NULL));
	BN_set_word(bn_size, sampleSize);
	BN_zero(bn_max);
	BN_copy(bn_min, tab[0]);

	if (pointsList == NULL) {
		printf("### ERROR pointsList\n");
		exit(EXIT_FAILURE);
	}

	if (mono) { hue = (double)rand() / (double)(RAND_MAX - 1); }

	for (i=0; i<sampleSize; i++) {
		if (mono) {
			if (i == 0) { hue = (double)rand() / (double)(RAND_MAX - 1); }
		} else {
			hue = (double)i / (double)sampleSize;
		}
		hsv2rgb(hue, 1.0, 1.0, &(pointsList[i].r), &(pointsList[i].g), &(pointsList[i].b));
		BN_add(bn_sum, bn_sum, tab[i]);
		if (i>=3) {
			BN_sub(bn_x, tab[i-3], tab[i-2]);
			BN_sub(bn_y, tab[i-2], tab[i-1]);
			BN_sub(bn_z, tab[i-1], tab[i]);
			pointsList[i].x = toDouble(bn_x);
			pointsList[i].y = toDouble(bn_y);
			pointsList[i].z = toDouble(bn_z);
			if (maxAll < pointsList[i].x) maxAll = pointsList[i].x;
			if (BN_cmp(bn_max, tab[i]) < 0) BN_copy(bn_max, tab[i]);
			if (BN_cmp(bn_min, tab[i]) > 0) BN_copy(bn_min, tab[i]);
		} else {
			pointsList[i].x = 0;
			pointsList[i].y = 0;
			pointsList[i].z = 0;
		}
	}
	BN_div(bn_average, bn_rem, bn_sum, bn_size, ctx);
	for (i=0; i<sampleSize; i++) {
		pointsList[i].x = pointsList[i].x * 25.0 / maxAll;
		pointsList[i].y = pointsList[i].y * 25.0 / maxAll;
		pointsList[i].z = pointsList[i].z * 25.0 / maxAll;
	}
	BN_clear_free(bn_x);
	BN_clear_free(bn_y);
	BN_clear_free(bn_z);
	BN_clear_free(bn_rem);
	BN_clear_free(bn_size);
	BN_CTX_free(ctx);
}


void populateHilbert(BIGNUM *tab[]) {
	unsigned long i;
	double hue = 0.0, x0 = 9.0, y0 = -25.0, z0 = -25.0, current = 0, max = 0;
	int order = 0;
	BIGNUM *bn_current = BN_new();
	order = determineHilbertOrder();
	hilbertSize = pow(4,order);
	hilbertPointList = (point*)calloc(hilbertSize, sizeof(point));
	if (hilbertPointList == NULL) {
		printf("### ERROR hilbertPointList\n");
		exit(EXIT_FAILURE);
	}
	hilbert(x0, y0, z0, order*2.0, 0.0, 0.0, order*2.0, order);
	printf("INFO: hilbert order %d (%lu points)\n", order, hilbertSize);
	max = toDouble(bn_max);
	for (i=0; i<hilbertSize; i++) {
		if (i<sampleSize) {
			BN_copy(bn_current, tab[i]);
			current = toDouble(bn_current);
			hue = current / max;
			hsv2rgb(hue, 0.8, 1.0, &(hilbertPointList[i].r), &(hilbertPointList[i].g), &(hilbertPointList[i].b));
		} else {
			hsv2rgb(1.0, 0.0, 1.0, &(hilbertPointList[i].r), &(hilbertPointList[i].g), &(hilbertPointList[i].b));
		}
		//printf("%ld\t%15.15f, %15.15f, %15.15f\t%1.15f, %1.15f, %1.15f\n", i, hilbertPointList[i].x, hilbertPointList[i].y, hilbertPointList[i].z, hilbertPointList[i].r, hilbertPointList[i].g, hilbertPointList[i].b);
	}
	BN_clear_free(bn_current);
}


long countFileLines(char *name) {
	long count = 0;
	char ch='\0';
	FILE *fic = fopen(name, "r");
	if (fic != NULL) {
		while (ch != EOF) {
			ch = fgetc(fic);
			if (ch == '\n')  count++;
		}
		fclose(fic);
	} else {
		printf("### ERROR open file error\n");
		exit(EXIT_FAILURE);
	}
	return count;
}


void playFile(int argc, char *argv[]) {
	unsigned long i=0;
	FILE *fic = fopen(argv[1], "r");
	char *line = NULL;
	size_t linecap = 0;
	ssize_t linelen;

	if (fic != NULL) {
		printf("INFO: file open\n");
		while ((linelen = getline(&line, &linecap, fic)) > 0) {
			line[strlen(line)-1]='\0';
			randList[i] = BN_new();
			BN_hex2bn(&randList[i], line);
			if (sampleSize < 100) { printf("%lu -> %s\n", i, BN_bn2hex(randList[i])); }
			i++;
		}
		fclose(fic);
		printf("INFO: file close\n");
		populatePoints(randList);
		populateHilbert(randList);
		glmain(argc, argv);
	} else {
		printf("### ERROR open file error\n");
		exit(EXIT_FAILURE);
	}
}


int main(int argc, char *argv[]) {
	switch (argc) {
		case 4:
			if (!strncmp(argv[2], "white", 5)) {
				background = 1;
			}
			if (!strncmp(argv[3], "mono", 4)) {
				mono = 1;
			}
			sampleSize = countFileLines(argv[1]);
			randListSize = sizeof(randList) / sizeof(randList[0]);
			if (sampleSize <= randListSize) {
				playFile(argc, argv);
				exit(EXIT_SUCCESS);
			} else {
				printf("INFO: Size exceeded\n");
				exit(EXIT_FAILURE);
			}
			break;
		default:
			usage();
			exit(EXIT_FAILURE);
			break;
	}
}
