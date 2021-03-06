/*visCipherCmp3d
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

#include <GL/freeglut.h>

#define WINDOW_TITLE_PREFIX "visCipherCmp3d"
#define couleur(param) printf("\033[%sm",param)

static short winSizeW = 920,
	winSizeH = 690,
	frame = 0,
	currentTime = 0,
	timebase = 0,
	fullScreen = 0,
	rotate = 0,
	dt = 5; // in milliseconds

static int textList = 0,
	objectList = 0,
	cpt = 0,
	background = 0;

static float fps = 0.0,
	rotx = -80.0,
	roty = 0.0,
	rotz = 20.0,
	xx = 0.0,
	yy = 5.0,
	zoom = 100.0,
	prevx = 0.0,
	prevy = 0.0,
	alpha = 0.0,
	pSize = 0.0,
	sphereRadius = 0.6,
	squareWidth = 0.055;

static BIGNUM *bn_sum, *bn_average, *bn_max, *bn_min;

typedef struct _point {
	GLdouble x, y, z;
	GLfloat r, g, b, a;
} point;


static point *pointsList = NULL;

static unsigned long sampleSize = 0,
	seuil = 60000;

static GLuint textureid = 0;

double maxAll = 0.0;


void usage(void) {
	couleur("31");
	printf("Michel Dubois -- visCipherCmp3d -- (c) 2013\n\n");
	couleur("0");
	printf("Syntaxe: visCipherCmp3d <filename1> <filename2> <background color>\n");
	printf("\t<filename1> -> file where the first sequence of the AES datas be stored\n");
	printf("\t<filename2> -> file where the second sequence of the AES datas be stored\n");
	printf("\t\t Both sequences must have the same length.\n");
	printf("\t<background color> -> 'white' or 'black'\n");
}


double distance(point p1, point p2) {
	double dx=0.0, dy=0.0, dz=0.0, dist=0.0;
	dx = p2.x - p1.x;
	dx = dx * dx;
	dy = p2.y - p1.y;
	dy = dy * dy;
	dz = p2.z - p1.z;
	dz = dz * dz;
	dist = sqrt(dx + dy + dz);
	return(dist);
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


void generateTexture(void) {
	int w=256, h=256, x=0, y=0, ofset=0;
	float halfw=0.0, halfh=0.0, xoffset=0.0, yoffsets=0.0, alpha=0.0;
	unsigned char *pixData = NULL;

	pixData = (unsigned char *)calloc(w*h*4, sizeof(unsigned char));
	halfw = w/2.0; halfh = h/2.0;
	for(y=0; y<h; ++y){
		for(x=0; x<w; ++x){
			ofset = (x + y*w) * 4;
			xoffset = ((float)x - halfw) / halfw;
			yoffsets = ((float)y - halfh) / halfh;
			alpha = 1.0f - sqrt(xoffset*xoffset + yoffsets*yoffsets);
			if(alpha < 0.0f) { alpha = 0.0f; }
			pixData[ofset + 0] = 255; //red
			pixData[ofset + 1] = 255; //greeen
			pixData[ofset + 2] = 255; //blue
			pixData[ofset + 3] = 255.0f * alpha; // alpha
		}
	}

	glGenTextures(1, &textureid);
	glActiveTexture(GL_TEXTURE0);
	//glEnable(GL_TEXTURE_2D);
	//glBindTexture(GL_TEXTURE_2D, textureid);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, pixData);
	//glEnable(GL_POINT_SPRITE);
	glTexEnvi(GL_POINT_SPRITE, GL_COORD_REPLACE, GL_TRUE);
	glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_REPLACE);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
	free(pixData);
}


void drawPoint(point p) {
	glPointSize(pSize);
	glColor4f(p.r, p.g, p.b, p.a);
	glBegin(GL_POINTS);
	glNormal3f(p.x, p.y, p.z);
	glVertex3f(p.x, p.y, p.z);
	glEnd();
}


void drawSphere(point p) {
	glColor4f(p.r, p.g, p.b, p.a);
	glTranslatef(p.x, p.y, p.z);
	glutSolidSphere(sphereRadius, 8, 8);
}


void drawSquare(point p) {
	glColor4f(p.r, p.g, p.b, p.a);
	glTranslatef(p.x, p.y, p.z);
	glBegin(GL_QUADS);
	glVertex3f(-squareWidth, -squareWidth, 0.0); // Bottom left corner
	glVertex3f(-squareWidth, squareWidth, 0.0); // Top left corner
	glVertex3f(squareWidth, squareWidth, 0.0); // Top right corner
	glVertex3f(squareWidth, -squareWidth, 0.0); // Bottom right corner
	glEnd();
}


void drawLine(point p1, point p2){
	double d = distance(p1, p2);
	double dx = p2.x - p1.x;
	double dy = p2.y - p1.y;
	double dz = p2.z - p1.z;
	glLineWidth(pSize);
	glColor4f(0.6f, 0.6f, 0.6f, alpha);
	glNormal3f(dx/d, dy/d, dz/d);
	glBegin(GL_LINES);
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
	sprintf(text1, "dt: %1.3f, FPS: %4.2f, Nbr elts: %ld", (dt/1000.0), fps, sampleSize*2);
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
	if (sampleSize*2 <= seuil) {
		objectList = glGenLists(1);
		glNewList(objectList, GL_COMPILE_AND_EXECUTE);
		for (i=0; i<sampleSize*2; i++) {
			glPushMatrix();
			if (i<sampleSize) {
				drawLine(pointsList[i], pointsList[i+sampleSize]);
			}
			drawSphere(pointsList[i]);
			glPopMatrix();
		}
		glEndList();
	}
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
	unsigned long i = 0;
	char *name = malloc(20 * sizeof(char));
	switch (key) {
		case 27: // Escape
			printf("x %d, y %d\n", x, y);
			printf("INFO: exit loop\n");
			glutLeaveMainLoop();
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
			printf("INFO: fullscreen %d\n", fullScreen);
			if (fullScreen) {
				glutFullScreen();
			} else {
				glutPositionWindow(120,10);
				glutReshapeWindow(winSizeW, winSizeH);
			}
			break;
		case 'a':
			alpha -= 0.05;
			if (alpha <= 0) { alpha = 1.0; }
			for (i=0; i<sampleSize*2; i++) {
				pointsList[i].a = alpha;
			}
			printf("INFO: alpha channel %f\n", alpha);
			break;
		case 's':
			pSize += 1.0;
			if (pSize >= 20) { pSize = 0.5; }
			printf("INFO: point size %f\n", pSize);
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

	glPushMatrix();
	glTranslatef(xx, yy, -zoom);
	glRotatef(rotx, 1.0, 0.0, 0.0);
	glRotatef(roty, 0.0, 1.0, 0.0);
	glRotatef(rotz, 0.0, 0.0, 1.0);

	GLfloat ambient1[] = {0.15f, 0.15f, 0.15f, 1.0f};
	GLfloat diffuse1[] = {0.8f, 0.8f, 0.8f, 1.0f};
	GLfloat specular1[] = {1.0f, 1.0f, 1.0f, 1.0f};
	GLfloat position1[] = {0.0f, 0.0f, 24.0f, 1.0f};
	glLightfv(GL_LIGHT1, GL_AMBIENT, ambient1);
	glLightfv(GL_LIGHT1, GL_DIFFUSE, diffuse1);
	glLightfv(GL_LIGHT1, GL_DIFFUSE, specular1);
	glLightfv(GL_LIGHT1, GL_POSITION, position1);
	glEnable(GL_LIGHT1);

	drawAxes();
	if (sampleSize >= seuil) {
		glPointSize(pSize);
		glEnableClientState(GL_VERTEX_ARRAY);
		glEnableClientState(GL_COLOR_ARRAY);
		glVertexPointer(3, GL_DOUBLE, 2*sizeof(point), pointsList);
		glColorPointer(4, GL_FLOAT, 2*sizeof(point), &pointsList[0].r);
		glDrawArrays(GL_POINTS, 0, sampleSize);
		glDisableClientState(GL_COLOR_ARRAY);
		glDisableClientState(GL_VERTEX_ARRAY);
	} else {
		glCallList(objectList);
	}
	glPopMatrix();

	glutPostRedisplay();
	glutSwapBuffers();
}


void init(void) {
	if (background){ // White background
		glClearColor(1.0, 1.0, 1.0, 1.0);
	} else { // Black background
		glClearColor(0.1, 0.1, 0.1, 1.0);
	}

	glEnable(GL_LIGHTING);

	GLfloat ambient[] = {0.05f, 0.05f, 0.05f, 1.0f};
	GLfloat diffuse[] = {0.8f, 0.8f, 0.8f, 1.0f};
	GLfloat specular[] = {1.0f, 1.0f, 1.0f, 1.0f};
	GLfloat position[] = {0.0f, 0.0f, 0.0f, 1.0f};
	glLightfv(GL_LIGHT0, GL_AMBIENT, ambient);
	glLightfv(GL_LIGHT0, GL_DIFFUSE, diffuse);
	glLightfv(GL_LIGHT0, GL_DIFFUSE, specular);
	glLightfv(GL_LIGHT0, GL_POSITION, position);
	glEnable(GL_LIGHT0);

	glEnable(GL_COLOR_MATERIAL);
	glColorMaterial(GL_FRONT, GL_AMBIENT_AND_DIFFUSE);
	GLfloat matAmbient[] = {0.3f, 0.3f, 0.3f, 1.0f};
	GLfloat matDiffuse[] = {0.6f, 0.6f, 0.6f, 1.0f};
	GLfloat matSpecular[] = {0.8f, 0.8f, 0.8f, 1.0f};
	GLfloat matShininess[] = {128.0f};
	glMaterialfv(GL_FRONT_AND_BACK, GL_AMBIENT, matAmbient);
	glMaterialfv(GL_FRONT_AND_BACK, GL_DIFFUSE, matDiffuse);
	glMaterialfv(GL_FRONT_AND_BACK, GL_SPECULAR, matSpecular);
	glMaterialfv(GL_FRONT_AND_BACK, GL_SHININESS, matShininess);

	GLfloat baseAmbient[] = {0.5f, 0.5f, 0.5f, 0.5f};
	glLightModelfv(GL_LIGHT_MODEL_AMBIENT, baseAmbient);
	glLightModeli(GL_LIGHT_MODEL_LOCAL_VIEWER, GL_TRUE);

	// points smoothing
	glEnable(GL_POINT_SMOOTH);
	glHint(GL_POINT_SMOOTH_HINT, GL_NICEST);

	//needed for transparency
	glEnable(GL_DEPTH_TEST);
	glDepthFunc(GL_LESS);
	glEnable(GL_BLEND);
	glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

	glShadeModel(GL_SMOOTH); // smooth shading
	glEnable(GL_NORMALIZE); // recalc normals for non-uniform scaling
	glEnable(GL_AUTO_NORMAL);

	glEnable(GL_CULL_FACE); // do not render back-faces, faster

	drawObject();
}


void glmain(int argc, char *argv[]) {
	glutInit(&argc, argv);
	glutInitDisplayMode(GLUT_RGBA | GLUT_DOUBLE | GLUT_DEPTH);
	glutInitWindowSize(winSizeW, winSizeH);
	glutInitWindowPosition(120, 10);
	glutCreateWindow(WINDOW_TITLE_PREFIX);
	glutDisplayFunc(display);
	glutReshapeFunc(onReshape);
	glutSpecialFunc(onSpecial);
	glutMotionFunc(onMotion);
	glutIdleFunc(onIdle);
	glutMouseFunc(onMouse);
	glutKeyboardFunc(onKeyboard);
	glutTimerFunc(dt, onTimer, 0);
	init();
	fprintf(stdout, "INFO: OpenGL Version: %s\n", glGetString(GL_VERSION));
	fprintf(stdout, "INFO: FreeGLUT Version: %d\n", glutGet(GLUT_VERSION));
	glutSetOption(GLUT_ACTION_ON_WINDOW_CLOSE, GLUT_ACTION_GLUTMAINLOOP_RETURNS);
	glutMainLoop();
	fprintf(stdout, "INFO: Freeing memory\n");
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


double minkowskiDistance(double p, point p1, point p2) {
	double tmp = 0.0;
	tmp = pow(fabs(p1.x-p2.x), (int)p) + pow(fabs(p1.y-p2.y), (int)p) + pow(fabs(p1.z-p2.z), (int)p);
	return(pow(tmp, (1.0/p)));
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
	pointsList = (point*)calloc(sampleSize*2, sizeof(point));
	srand(time(NULL));
	BN_set_word(bn_size, sampleSize*2);
	BN_zero(bn_max);
	BN_copy(bn_min, tab[0]);
	FILE *fic = fopen("distance.dat", "w");

	if (fic != NULL) { printf("INFO: file create\n"); }

	if (pointsList == NULL) {
		printf("### ERROR pointsList\n");
		exit(EXIT_FAILURE);
	}

	for (i=0; i<sampleSize*2; i++) {
		if ( i %sampleSize == 0) { hue = (double)rand() / (double)RAND_MAX; }
		hsv2rgb(hue, 1.0, 1.0, &(pointsList[i].r), &(pointsList[i].g), &(pointsList[i].b));
		pointsList[i].a = alpha;
		BN_add(bn_sum, bn_sum, tab[i]);
		if (i>=3) {
			BN_sub(bn_x, tab[i-3], tab[i-2]);
			BN_sub(bn_y, tab[i-2], tab[i-1]);
			BN_sub(bn_z, tab[i-1], tab[i]);
			if (BN_num_bits(bn_x) > 64) { // We have 128 bits blocs
				BN_rshift(bn_x, bn_x, 64); // bn_x = bn_x / 2^64
				BN_rshift(bn_y, bn_y, 64);
				BN_rshift(bn_z, bn_z, 64);
			}
			pointsList[i].x = toDouble(bn_x);
			pointsList[i].y = toDouble(bn_y);
			pointsList[i].z = toDouble(bn_z);
			if ((fic != NULL) & (i>=sampleSize)) {
				fprintf(fic, "%lf\n", minkowskiDistance(2.0, pointsList[i-sampleSize], pointsList[i]));
			}
			if (maxAll < pointsList[i].x) maxAll = pointsList[i].x;
			if (BN_cmp(bn_max, tab[i]) < 0) BN_copy(bn_max, tab[i]);
			if (BN_cmp(bn_min, tab[i]) > 0) BN_copy(bn_min, tab[i]);
		} else {
			pointsList[i].x = 0;
			pointsList[i].y = 0;
			pointsList[i].z = 0;
		}
	}
	if (fic != NULL) {
		fclose(fic);
		printf("INFO: file close\n");
	}
	BN_div(bn_average, bn_rem, bn_sum, bn_size, ctx);
	for (i=0; i<sampleSize*2; i++) {
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


unsigned long countFileLines(char *name) {
	unsigned long count = 0;
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
	BIGNUM *randList[sampleSize*2];
	FILE *fic1 = fopen(argv[1], "r");
	FILE *fic2 = fopen(argv[2], "r");
	char *line = NULL;
	size_t linecap = 0;
	ssize_t linelen;

	if ((fic1 == NULL) | (fic2 == NULL)) {
		printf("INFO: open error file 1\n");
		exit(EXIT_FAILURE);
	} else {
		printf("INFO: file 1 open\n");
		while ((linelen = getline(&line, &linecap, fic1)) > 0) {
			line[strlen(line)-1]='\0';
			randList[i] = BN_new();
			BN_hex2bn(&randList[i], line);
			i++;
		}
		fclose(fic1);
		printf("INFO: file 1 close\n");
		printf("INFO: file 2 open\n");
		while ((linelen = getline(&line, &linecap, fic2)) > 0) {
			line[strlen(line)-1]='\0';
			randList[i] = BN_new();
			BN_hex2bn(&randList[i], line);
			i++;
		}
		fclose(fic2);
		printf("INFO: file 2 close\n");
		populatePoints(randList);
		glmain(argc, argv);
	}
}


int main(int argc, char *argv[]) {
	switch (argc) {
		case 4:
			if (!strncmp(argv[3], "white", 5)) { background = 1; }
			alpha = 1.0f;
			pSize = 1.0f;
			sampleSize = countFileLines(argv[1]);
			if (countFileLines(argv[2]) != sampleSize) {
				usage();
				exit(EXIT_FAILURE);
			}
			playFile(argc, argv);
			exit(EXIT_SUCCESS);
			break;
		default:
			usage();
			exit(EXIT_FAILURE);
			break;
	}
}
