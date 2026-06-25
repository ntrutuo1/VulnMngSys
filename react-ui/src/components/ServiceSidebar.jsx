import { Badge, Button, Tree, Typography } from 'antd'
import { AppstoreOutlined, FolderOpenOutlined, ProfileOutlined } from '@ant-design/icons'
import { groupStatus } from './serviceGroups'

function statusColor(status) {
  if (status === 'fail') return '#dc2626'
  if (status === 'manual') return '#d97706'
  return '#16a34a'
}

function nodeTitle(group) {
  const status = groupStatus(group)
  return (
    <span className="service-tree-node">
      <span className="service-tree-label">{group.label || group.serviceId}</span>
      <Badge
        color={statusColor(status)}
        count={`${group.failed || 0}/${group.total || 0}`}
        overflowCount={9999}
        className="service-tree-badge"
      />
    </span>
  )
}

function toTreeNode(group) {
  const children = (group.subgroups || []).map(toTreeNode)
  return {
    key: group.serviceId,
    title: nodeTitle(group),
    icon: children.length > 0 ? <FolderOpenOutlined /> : <ProfileOutlined />,
    children,
  }
}

export default function ServiceSidebar({ groups = [], selectedService, total = 0, onSelect }) {
  const selectedKeys = selectedService ? [selectedService] : ['all']
  const treeData = [
    {
      key: 'all',
      title: (
        <span className="service-tree-node">
          <span className="service-tree-label">All Services</span>
          <Badge count={total} overflowCount={9999} className="service-tree-badge" />
        </span>
      ),
      icon: <AppstoreOutlined />,
    },
    ...groups.map(toTreeNode),
  ]

  return (
    <aside className="service-sidebar">
      <div className="service-sidebar-head">
        <Typography.Text strong>Services</Typography.Text>
        {selectedService ? (
          <Button type="link" size="small" onClick={() => onSelect(null)}>
            Clear
          </Button>
        ) : null}
      </div>
      <Tree
        showIcon
        blockNode
        defaultExpandAll
        selectedKeys={selectedKeys}
        treeData={treeData}
        onSelect={(keys) => {
          const key = keys[0]
          onSelect(key && key !== 'all' ? key : null)
        }}
      />
    </aside>
  )
}
