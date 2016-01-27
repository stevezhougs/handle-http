/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "util.h"

#include <time.h>
#include <ctype.h>


inline int32_t zGetTimestamp()
{
	return (int32_t)time(NULL);
}

void zGetLocalTimeEx(char tt[])
{
	time_t t = time(0);
	strftime(tt, sizeof(tt), "%Y-%m-%d %X",localtime(&t) );
}

void zPrintRawDataFp(FILE *fp, uint8_t *buf, uint32_t buflen)
{
	if(NULL == fp)
		fp = stdout;

    int ch = 0;
    uint32_t u = 0;

    for (u = 0; u < buflen; u+=16) {
        fprintf(fp ," %04X  ", u);
        for (ch = 0; (u+ch) < buflen && ch < 16; ch++) {
             fprintf(fp, "%02X ", (uint8_t)buf[u+ch]);

             if (ch == 7) fprintf(fp, " ");
        }
        if (ch == 16) fprintf(fp, "  ");
        else if (ch < 8) {
            int spaces = (16 - ch) * 3 + 2 + 1;
            int s = 0;
            for ( ; s < spaces; s++) fprintf(fp, " ");
        } else if(ch < 16) {
            int spaces = (16 - ch) * 3 + 2;
            int s = 0;
            for ( ; s < spaces; s++) fprintf(fp, " ");
        }

        for (ch = 0; (u+ch) < buflen && ch < 16; ch++) {
             fprintf(fp, "%c", isprint((uint8_t)buf[u+ch]) ? (uint8_t)buf[u+ch] : '.');

             if (ch == 7)  fprintf(fp, " ");
             if (ch == 15) fprintf(fp, "\n");
        }
    }
    if (ch != 16)
        fprintf(fp, "\n");
}

void zPrintData(uint8_t *buf, uint32_t buflen)
{
    uint32_t u = 0;
    for (u = 0; u < buflen; ++u) 
	{	
		fprintf(stdout, "%c", (uint8_t)buf[u]);
	}
	fprintf(stdout, "\n");
}

/**
 * \brief Maps a string name to an enum value from the supplied table.  Please
 *        specify the last element of any map table with a {NULL, -1}.  If
 *        missing, you will be welcomed with a segfault :)
 *
 * \param enum_name Character string that has to be mapped to an enum value
 *                  from the table
 * \param table     Enum-Char table, from which the mapping is retrieved
 *
 * \retval result The enum_value for the enum_name string or -1 on failure
 */
int zMapEnumNameToValue(const char *enum_name, zEnumCharMap *table)
{
    int result = -1;

    if (enum_name == NULL || table == NULL) {
        printf("Invalid argument(s) passed into SCMapEnumNameToValue\n");
        return -1;
    }

    for (; table->enum_name != NULL; table++) {
        if (strcasecmp(table->enum_name, enum_name) == 0) {
            result = table->enum_value;
            break;
        }
    }

    return result;
}

/**
 * \brief Maps an enum value to a string name, from the supplied table
 *
 * \param enum_value Enum_value that has to be mapped to a string_value
 *                   from the table
 * \param table      Enum-Char table, from which the mapping is retrieved
 *
 * \retval result The enum_name for the enum_value supplied or NULL on failure
 */
const char * zMapEnumValueToName(int enum_value, zEnumCharMap *table)
{
    if (table == NULL) {
        printf("Invalid argument(s) passed into SCMapEnumValueToName\n");
        return NULL;
    }

    for (; table->enum_name != NULL; table++) {
        if (table->enum_value == enum_value) {
            return table->enum_name;
        }
    }

    printf("A enum by the value %d doesn't exist in this table\n", enum_value);

    return NULL;
}


