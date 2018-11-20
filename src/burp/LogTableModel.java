package burp;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// extend AbstractTableModel to draw the log table
//    
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.util.ArrayList;

public class LogTableModel extends AbstractTableModel { 
	

    private final ArrayList<BurpHttpMessage> messages;

	public LogTableModel(ArrayList<BurpHttpMessage> messages){
		super();
		this.messages = messages;
	}
	
	@Override
	public int getColumnCount(){ return 4; } 
	
	@Override
	public int getRowCount(){ return messages.size();} 
	
	@Override
	public Object getValueAt(int row,int col){
		switch (col){
			case 0:
				return row;
			case 1:
				return messages.get(row).getTimeString();
			case 2:
				return messages.get(row).getProtocol()+"://"+messages.get(row).getHost();
			case 3:
				return messages.get(row).getHostIP();
			default:
				return "";
		} 
	}    
	
	@Override
	public String getColumnName(int columnIndex){
		switch(columnIndex){
			case 0:
				return "#";
			case 1:
				return "Time";
			case 2:
				return "Host";
			case 3:
				return "IP";
			default:
				return "";
		}
	} 
	
	public void update(BurpHttpMessage m){
		messages.add(m);
		fireTableRowsInserted(1,1);
	} 
}
