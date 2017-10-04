package freenet.client.filter;

import java.io.IOException;
import java.io.InputStream;

import junit.framework.TestCase;
import freenet.support.api.Bucket;
import freenet.support.io.ArrayBucket;
import freenet.support.io.BucketTools;
import freenet.support.io.NullBucket;

public class PNGFilterTest extends TestCase {
	protected static Object[][] testImages = {
			// { image file, valid }
	        // NOT PASS  { "./png/broken/scal_floating_point.png", false }, //
	        // NOT PASS  { "./png/broken/splt_length_mod_10.png", false }, //
	        // NOT PASS  { "./png/broken/length_ster.png", false }, //
	        // NOT PASS  { "./png/broken/scal_unit_specifier.png", false }, //
	        { "./png/broken/nonconsecutive_idat.png", false }, //
	        // NOT PASS  { "./png/broken/plte_too_many_entries.png", false }, //
	        // NOT PASS  { "./png/broken/private_filter_method.png", false }, //
	        // NOT PASS  { "./png/broken/truncate_idat_1.png", false }, //
	        // NOT PASS  { "./png/broken/length_iend.png", false }, //
	        // NOT PASS  { "./png/broken/ihdr_bit_depth.png", false }, //
	        // NOT PASS  { "./png/broken/multiple_scal.png", false }, //
	        // NOT PASS  { "./png/broken/chunk_type.png", false }, //
	        // NOT PASS  { "./png/broken/plte_too_many_entries_2.png", false }, //
	        // NOT PASS  { "./png/broken/length_offs.png", false }, //
	        // NOT PASS  { "./png/broken/truncate_idat_0.png", false }, //
	        // NOT PASS  { "./png/broken/length_gama.png", false }, //
	        { "./png/broken/truncate_zlib_2.png", false }, //
	        // NOT PASS  { "./png/broken/private_filter_type.png", false }, //
	        // NOT PASS  { "./png/broken/sbit_after_plte.png", false }, //
	        // NOT PASS  { "./png/broken/missing_idat.png", false }, //
	        // NOT PASS  { "./png/broken/ihdr_filter_method.png", false }, //
	        // NOT PASS  { "./png/broken/ihdr_compression_method.png", false }, //
	        // NOT PASS  { "./png/broken/pcal_after_idat.png", false }, //
	        { "./png/broken/plte_after_idat.png", false }, //
	        // NOT PASS  { "./png/broken/chunk_private_critical.png", false }, //
	        // NOT PASS  { "./png/broken/splt_duplicate_name.png", false }, //
	        { "./png/broken/chunk_length.png", false }, //
	        // NOT PASS  { "./png/broken/scal_after_idat.png", false }, //
	        { "./png/broken/chunk_crc.png", false }, //
	        // NOT PASS  { "./png/broken/ihdr_interlace_method.png", false }, //
	        // NOT PASS  { "./png/broken/ihdr_1bit_alpha.png", false }, //
	        // NOT PASS  { "./png/broken/ihdr_color_type.png", false }, //
	        // NOT PASS  { "./png/broken/multiple_plte.png", false }, //
	        // NOT PASS  { "./png/broken/multiple_ster.png", false }, //
	        // NOT PASS  { "./png/broken/length_sbit.png", false }, //
	        // NOT PASS  { "./png/broken/splt_length_mod_6.png", false }, //
	        // NOT PASS  { "./png/broken/length_sbit_2.png", false }, //
	        // NOT PASS  { "./png/broken/trns_bad_color_type.png", false }, //
	        // NOT PASS  { "./png/broken/multiple_gama.png", false }, //
	        // NOT PASS  { "./png/broken/offs_after_idat.png", false }, //
	        // NOT PASS  { "./png/broken/length_ihdr.png", false }, //
	        { "./png/broken/missing_ihdr.png", false }, //
	        // NOT PASS  { "./png/broken/ihdr_image_size.png", false }, //
	        // NOT PASS  { "./png/broken/gama_after_plte.png", false }, //
	        { "./png/broken/multiple_ihdr.png", false }, //
	        // NOT PASS  { "./png/broken/unknown_filter_type.png", false }, //
	        // NOT PASS  { "./png/broken/scal_zero.png", false }, //
	        { "./png/broken/truncate_zlib.png", false }, //
	        // NOT PASS  { "./png/broken/scal_negative.png", false }, //
	        // NOT PASS  { "./png/broken/ster_mode.png", false }, //
	        // NOT PASS  { "./png/broken/private_interlace_method.png", false }, //
	        // NOT PASS  { "./png/broken/srgb_after_idat.png", false }, //
	        // NOT PASS  { "./png/broken/ster_after_idat.png", false }, //
	        // NOT PASS  { "./png/broken/ihdr_16bit_palette.png", false }, //
	        // NOT PASS  { "./png/broken/iccp_after_idat.png", false }, //
	        // NOT PASS  { "./png/broken/plte_empty.png", false }, //
	        // NOT PASS  { "./png/broken/private_compression_method.png", false }, //
	        // NOT PASS  { "./png/broken/offs_unit_specifier.png", false }, //
	        // NOT PASS  { "./png/broken/plte_length_mod_three.png", false }, //
	        // NOT PASS  { "./png/broken/multiple_offs.png", false }, //
	        // NOT PASS  { "./png/broken/gama_after_idat.png", false }, //
	        // NOT PASS  { "./png/broken/missing_plte.png", false }, //
	        // NOT PASS  { "./png/broken/splt_sample_depth.png", false }, //
	        // NOT PASS  { "./png/broken/multiple_pcal.png", false }, //
	        // NOT PASS  { "./png/broken/plte_in_grayscale.png", false }, //
	        { "./png/misc/pngbar.png", true }, //
	        { "./png/misc/pngnow.png", true }, //
	        { "./png/misc/pngtest.png", true }, //
	        { "./png/suite/basn2c16.png", true }, //
	        { "./png/suite/basn3p01.png", true }, //
	        { "./png/suite/basn2c08.png", true }, //
	        { "./png/suite/basn3p04.png", true }, //
	        { "./png/suite/basn0g16.png", true }, //
	        { "./png/suite/basn0g08.png", true }, //
	        { "./png/suite/basn0g02.png", true }, //
	        { "./png/suite/basn4a08.png", true }, //
	        { "./png/suite/basn6a08.png", true }, //
	        { "./png/suite/basn6a16.png", true }, //
	        { "./png/suite/basn4a16.png", true }, //
	        { "./png/suite/basn0g01.png", true }, //
	        { "./png/suite/basn3p08.png", true }, //
	        { "./png/suite/basn3p02.png", true }, //
	        { "./png/suite/basn0g04.png", true }, //
	};

	public void testSuiteTest() throws IOException {
		PNGFilter filter = new PNGFilter(false, false, true);

		for (Object[] test : testImages) {
			String filename = (String) test[0];
			boolean valid = (Boolean) test[1];
			Bucket ib;
			try {
				ib = resourceToBucket(filename);
			} catch (IOException e) {
				System.out.println(filename + " not found, test skipped");
				continue;
			}

			try {
				filter.readFilter(ib.getInputStream(), new NullBucket().getOutputStream(), "", null);

				assertTrue(filename + " should " + (valid ? "" : "not ") + "be valid", valid);
			} catch (DataFilterException dfe) {
				assertFalse(filename + " should " + (valid ? "" : "not ") + "be valid", valid);
			}
		}
	}

	protected Bucket resourceToBucket(String filename) throws IOException {
		InputStream is = getClass().getResourceAsStream(filename);
		if (is == null) throw new java.io.FileNotFoundException();
		ArrayBucket ab = new ArrayBucket();
		BucketTools.copyFrom(ab, is, Long.MAX_VALUE);
		return ab;
	}
}
