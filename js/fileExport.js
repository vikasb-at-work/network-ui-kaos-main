 /**
 * Based on
 * Daniel Blanco Parla
 * https://github.com/deblanco/xlsExport
 *
 * Also uses SheetsJS from here: 
 * https://docs.sheetjs.com/docs/getting-started/installation/standalone/#vendoring
 * This allows us to have the most compaitble output and allows for a lot of features
 * we aren't currently using.
 * 
 * Requires xlsx.full.min.js to be loaded in the scripts section of your html
 */

class fileExport {
    // data: array of objects with the data for each row of the table
    // name: title for the worksheet
    constructor(data, title = 'Worksheet') {
      // input validation: new XlsExport([], String)
      if (!Array.isArray(data) || data.length === 0 || typeof title !== 'string' || title.trim() === '') {
        throw new Error('Invalid input: new XlsExport(Array, String)');
      }
  
      this._data = data;
      this._title = title;
    }
  
    set data(data) {
      if (!Array.isArray(data)) throw new Error('Invalid input type: data must be an Array');
      this._data = data;
    }
  
    get data() {
      return this._data;
    }
    exportToXLSX(fileName = 'export.xlsx') {
        // Create a new workbook
        const ws = XLSX.utils.json_to_sheet(this._data); // Convert JSON to sheet
        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, ws, this._title); // Append worksheet to workbook
    
        // Write the workbook and trigger the download
        XLSX.writeFile(wb, fileName);
    }

    exportToCSV(fileName = 'export.csv') {
        const ws = XLSX.utils.json_to_sheet(this._data);
        const csv = XLSX.utils.sheet_to_csv(ws);
    
        const csvBlob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
        const csvLink = window.URL.createObjectURL(csvBlob);
        this.downloadFile(csvLink, fileName);
    }

    downloadFile(output, fileName) {
      const link = document.createElement('a');
      document.body.appendChild(link);
      link.download = fileName;
      link.href = output;
      link.click();
      document.body.removeChild(link);
    }

  }